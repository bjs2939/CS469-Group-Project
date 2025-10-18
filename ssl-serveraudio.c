/**
 * @file ssl-serveraudio.c
 * @authors ** Kenneth Sherwood, Thomas Wintenburg, Bradley Spence **
 * @date ** 10/14/2025 **
 * @brief tls mp3 server: list dirs, list files in dir, get file
 *
 * proto (line-based):
 *   LISTDIR                 -> lists subdirs under ROOT_DIR
 *   LIST                    -> lists files in ROOT_DIR (top-level)
 *   LIST <dirname>          -> lists files inside subdir
 *   GET <relpath>           -> "file" or "dir/file" (one slash max)
 *   QUIT
 */

#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>

#define DEFAULT_PORT 4433
#define ROOT_DIR "./media"
#define CERTIFICATE_FILE "cert.pem"
#define KEY_FILE        "key.pem"
#define BUF_SZ 8192
#define MAX_LINE 512
#define MAX_PENDING_CONNECTIONS 16

// per-client ctx
typedef struct {
    int client_fd;
    SSL *ssl;
    struct sockaddr_in addr;
} client_ctx_t;

// init sockets
static void init_openssl(void);
static SSL_CTX *make_ctx(void);
static int create_server_socket(uint16_t port);

// main loop + per-client
static void server_loop(int server_fd, SSL_CTX *ctx);
static void *serve_one(void *arg);
static void handle_client_connection(client_ctx_t *ctx);

// utils (log, io, validation)
static void util_die(const char *fmt, ...);
static void util_log_msg(const char *fmt, ...);
static ssize_t util_ssl_readline(SSL *ssl, char *buf, size_t cap);
static int util_send_all_ssl(SSL *ssl, const void *buf, size_t len);
static bool util_valid_component(const char *s);
static bool util_safe_relpath(const char *path);

// listing + get
static int util_handle_list_dirs(SSL *ssl);
static int util_handle_list_in_dir(SSL *ssl, const char *dirname); // "." means ROOT
static int util_handle_get(SSL *ssl, const char *relpath);

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);

    int port = (argc >= 2) ? atoi(argv[1]) : DEFAULT_PORT;

    // ensure media dir exists
    struct stat st;
    if (stat(ROOT_DIR, &st) != 0 || !S_ISDIR(st.st_mode)) {
        util_die("create %s and put mp3s there", ROOT_DIR);
    }

    init_openssl();
    SSL_CTX *ctx = make_ctx();
    int server_fd = create_server_socket((uint16_t)port);

    util_log_msg("listening on %d. serving from %s", port, ROOT_DIR);
    server_loop(server_fd, ctx);

    close(server_fd);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}

// init + sockets 

static void init_openssl(void) {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

static SSL_CTX *make_ctx(void) {
    const SSL_METHOD *m = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(m);
    if (!ctx) util_die("SSL_CTX_new failed");

    // cert + key
    if (SSL_CTX_use_certificate_file(ctx, CERTIFICATE_FILE, SSL_FILETYPE_PEM) <= 0)
        util_die("use_certificate_file failed");
    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0)
        util_die("use_privatekey_file failed");
    if (!SSL_CTX_check_private_key(ctx))
        util_die("private key mismatch");

#ifdef TLS1_3_VERSION
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
#endif
    return ctx;
}

static int create_server_socket(uint16_t port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) util_die("socket: %s", strerror(errno));
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = htons(port);
    if (bind(s, (struct sockaddr *)&a, sizeof(a)) < 0)
        util_die("bind: %s", strerror(errno));
    if (listen(s, MAX_PENDING_CONNECTIONS) < 0)
        util_die("listen: %s", strerror(errno));
    return s;
}

// loop + per-client

static void server_loop(int server_fd, SSL_CTX *ctx) {
    while (1) {
        struct sockaddr_in ca; socklen_t clen = sizeof ca;
        int cfd = accept(server_fd, (struct sockaddr *)&ca, &clen);
        if (cfd < 0) { perror("accept"); continue; }

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, cfd);

        client_ctx_t *cc = calloc(1, sizeof *cc);
        cc->client_fd = cfd;
        cc->ssl = ssl;
        cc->addr = ca;

        pthread_t th;
        if (pthread_create(&th, NULL, serve_one, cc) != 0) {
            perror("pthread_create");
            SSL_free(ssl);
            close(cfd);
            free(cc);
            continue;
        }
        pthread_detach(th);
    }
}

static void *serve_one(void *arg) {
    client_ctx_t *c = (client_ctx_t *)arg;
    handle_client_connection(c);

    // cleanup
    SSL_shutdown(c->ssl);
    SSL_free(c->ssl);
    close(c->client_fd);
    free(c);
    return NULL;
}




static void handle_client_connection(client_ctx_t *ctx) {
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ctx->addr.sin_addr, ip, sizeof ip);
    util_log_msg("client connected from %s", ip);

    if (SSL_accept(ctx->ssl) <= 0) { ERR_print_errors_fp(stderr); return; }

    char line[MAX_LINE];
    while (1) {
        ssize_t r = util_ssl_readline(ctx->ssl, line, sizeof line);
        if (r <= 0) { fprintf(stderr,"[server:handle_client_connection] disconnect/read err\n"); break; }
        fprintf(stderr,"[server:handle_client_connection] cmd='%s'\n", line);

        if (strcmp(line, "LISTDIR") == 0) {
            int rc = util_handle_list_dirs(ctx->ssl);
            fprintf(stderr,"[server:handle_client_connection] LISTDIR rc=%d\n", rc);
            if (rc != 0) break;
        } else if (strcmp(line, "LIST") == 0) {
            int rc = util_handle_list_in_dir(ctx->ssl, ".");
            fprintf(stderr,"[server:handle_client_connection] LIST '.' rc=%d\n", rc);
            if (rc != 0) break;
        } else if (strncmp(line, "LIST ", 5) == 0) {
            const char *dirname = line + 5;
            int rc = util_handle_list_in_dir(ctx->ssl, dirname);
            fprintf(stderr,"[server:handle_client_connection] LIST '%s' rc=%d\n", dirname, rc);
            if (rc != 0) break;
        } else if (strncmp(line, "GET ", 4) == 0) {
            const char *rel = line + 4;
            int rc = util_handle_get(ctx->ssl, rel);
            fprintf(stderr,"[server:handle_client_connection] GET '%s' rc=%d\n", rel, rc);
            if (rc != 0) break;
        } else if (strcmp(line, "QUIT") == 0) {
            util_send_all_ssl(ctx->ssl, "OK BYE\n", 7);
            fprintf(stderr,"[server:handle_client_connection] QUIT\n");
            break;
        } else {
            util_send_all_ssl(ctx->ssl, "ERR CMD\n", 8);
            fprintf(stderr,"[server:handle_client_connection] unknown cmd\n");
        }
    }
} //END static void handle_client_connection


// utils

static void util_die(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap); va_end(ap);
    fprintf(stderr, "\n");
    exit(EXIT_FAILURE);
}

static void util_log_msg(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vfprintf(stdout, fmt, ap); va_end(ap);
    fprintf(stdout, "\n"); fflush(stdout);
}

// read a single line (nl-terminated). trims cr/lf
static ssize_t util_ssl_readline(SSL *ssl, char *buf, size_t cap) {
    size_t n = 0;
    while (n + 1 < cap) {
        char c;
        int r = SSL_read(ssl, &c, 1);
        if (r <= 0) {
            int err = SSL_get_error(ssl, r);
            fprintf(stderr,"[server:readline] r=%d err=%d n=%zu\n", r, err, n);
            return (n==0) ? r : (ssize_t)n;
        }
        buf[n++] = c;
        if (c == '\n') break;
    }
    buf[n] = 0;
    while (n && (buf[n-1]=='\n' || buf[n-1]=='\r')) buf[--n] = 0;
    fprintf(stderr,"[server:readline] got line='%s'\n", buf);
    return (ssize_t)n;
}


// write all bytes
static int util_send_all_ssl(SSL *ssl, const void *buf, size_t len) {
    const unsigned char *p = buf;
    while (len) {
        int w = SSL_write(ssl, p, (int)((len > INT_MAX) ? INT_MAX : len));
        if (w <= 0) return -1;
        p += w; len -= w;
    }
    return 0;
}

// validate a single path component (no slashes)
static bool util_valid_component(const char *s) {
    if (!s || !*s) return false;
    if (strstr(s, "..")) return false;
    for (const unsigned char *p = (const unsigned char*)s; *p; ++p) {
        unsigned char c = *p;
        if (c=='/' || c=='\\') return false;
        if (!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||
              c==' '||c=='-'||c=='_'||c=='.'||c=='\''||c=='&'||
              c==','||c=='('||c==')'||c=='['||c==']')) return false;
    }
    return true;
}

// allow "file" or "dir/file" (one slash max). both parts validated
static bool util_safe_relpath(const char *path) {
    if (!path || !*path) return false;
    if (*path=='/' || *path=='\\') return false;
    if (strstr(path, "..")) return false;

    const char *slash = strchr(path, '/');
    if (!slash) {
        // single component
        return util_valid_component(path);
    }
    // exactly one slash, non-empty parts
    const char *first = path;
    const char *second = slash + 1;
    if (*second == 0) return false;
    if (strchr(second, '/')) return false;

    char a[256], b[256];
    size_t la = (size_t)(slash - first);
    if (la==0 || la>=sizeof(a)) return false;
    size_t lb = strlen(second);
    if (lb==0 || lb>=sizeof(b)) return false;
    memcpy(a, first, la); a[la]=0;
    memcpy(b, second, lb); b[lb]=0;
    return util_valid_component(a) && util_valid_component(b);
}

// --- listing + get ---


// list subdirs under ROOT_DIR

static int util_handle_list_dirs(SSL *ssl) {
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof cwd)) fprintf(stderr,"[server:LISTDIR] cwd=%s\n", cwd);
    fprintf(stderr,"[server:LISTDIR] root=%s\n", ROOT_DIR);

    DIR *d = opendir(ROOT_DIR);
    if (!d) {
        fprintf(stderr,"[server:LISTDIR] opendir fail\n");
        return util_send_all_ssl(ssl, "ERR OPEN\n", 9);
    }

    size_t count = 0;
    struct dirent *ent;
    while ((ent = readdir(d))) {
        if (!strcmp(ent->d_name,".") || !strcmp(ent->d_name,"..")) continue;
        char path[PATH_MAX];
        int n = snprintf(path, sizeof path, "%s/%s", ROOT_DIR, ent->d_name);
        if (n < 0 || (size_t)n >= sizeof(path)) continue;
        struct stat st;
        if (stat(path, &st)==0 && S_ISDIR(st.st_mode)) {
            fprintf(stderr,"[server:LISTDIR] dir=%s\n", ent->d_name);
            count++;
        }
    }
    rewinddir(d);

    char hdr[MAX_LINE];
    int hn = snprintf(hdr, sizeof hdr, "OK %zu\n", count);
    if (hn < 0 || (size_t)hn >= sizeof(hdr) || util_send_all_ssl(ssl, hdr, (size_t)hn) != 0) {
        closedir(d);
        fprintf(stderr,"[server:LISTDIR] send hdr fail\n");
        return -1;
    }

    while ((ent = readdir(d))) {
        if (!strcmp(ent->d_name,".") || !strcmp(ent->d_name,"..")) continue;
        char path[PATH_MAX];
        int n = snprintf(path, sizeof path, "%s/%s", ROOT_DIR, ent->d_name);
        if (n < 0 || (size_t)n >= sizeof(path)) continue;
        struct stat st;
        if (stat(path, &st)==0 && S_ISDIR(st.st_mode)) {
            char line[MAX_LINE];
            int ln = snprintf(line, sizeof line, "%s\n", ent->d_name);
            if (ln > 0 && (size_t)ln < sizeof(line)) util_send_all_ssl(ssl, line, (size_t)ln);
        }
    }
    closedir(d);
    fprintf(stderr,"[server:LISTDIR] sent %zu dirs\n", count);
    return 0;
}




// list files in dir: dirname == "." -> root
static int util_handle_list_in_dir(SSL *ssl, const char *dirname) {
    char base[PATH_MAX];

    // build base path
    if (strcmp(dirname, ".") == 0) {
        // root
        int n = snprintf(base, sizeof base, "%s", ROOT_DIR);
        if (n < 0 || (size_t)n >= sizeof(base)) {
            const char *msg = "ERR PATH\n";
            return util_send_all_ssl(ssl, msg, strlen(msg));
        }
    } else {
        // validate single component dir name
        if (!util_valid_component(dirname)) {
            const char *msg = "ERR NAME\n";
            return util_send_all_ssl(ssl, msg, strlen(msg));
        }
        // guard length before join: root + "/" + dirname
        size_t rlen = strnlen(ROOT_DIR, PATH_MAX);
        size_t dlen = strnlen(dirname, 256); // typical name_max
        if (rlen + 1 + dlen >= sizeof(base)) {
            const char *msg = "ERR PATH\n";
            return util_send_all_ssl(ssl, msg, strlen(msg));
        }
        snprintf(base, sizeof base, "%s/%s", ROOT_DIR, dirname);
    }

    DIR *d = opendir(base);
    if (!d) {
        const char *msg = "ERR OPEN\n";
        return util_send_all_ssl(ssl, msg, strlen(msg));
    }

    // pass 1: count regular files
    size_t count = 0;
    struct dirent *ent;
    while ((ent = readdir(d))) {
        if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) continue;

        // build p = base + "/" + name with guard
        char p[PATH_MAX];
        size_t blen = strnlen(base, sizeof(base));
        size_t nlen = strnlen(ent->d_name, 256);
        if (blen + 1 + nlen >= sizeof(p)) {
            // too long -> skip
            continue;
        }
        snprintf(p, sizeof p, "%s/%s", base, ent->d_name);

        struct stat st;
        if (stat(p, &st) == 0 && S_ISREG(st.st_mode)) count++;
    }
    rewinddir(d);

    // send header
    char hdr[MAX_LINE];
    int hn = snprintf(hdr, sizeof hdr, "OK %zu\n", count);
    if (hn < 0 || (size_t)hn >= sizeof(hdr) ||
        util_send_all_ssl(ssl, hdr, strlen(hdr)) != 0) {
        closedir(d);
        return -1;
    }

    // pass 2: send file names (only regular files)
    while ((ent = readdir(d))) {
        if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) continue;

        char p[PATH_MAX];
        size_t blen = strnlen(base, sizeof(base));
        size_t nlen = strnlen(ent->d_name, 256);
        if (blen + 1 + nlen >= sizeof(p)) {
            continue; // skip too-long path
        }
        snprintf(p, sizeof p, "%s/%s", base, ent->d_name);

        struct stat st;
        if (stat(p, &st) == 0 && S_ISREG(st.st_mode)) {
            char line[MAX_LINE];
            int ln = snprintf(line, sizeof line, "%s\n", ent->d_name);
            if (ln < 0 || (size_t)ln >= sizeof(line) ||
                util_send_all_ssl(ssl, line, strlen(line)) != 0) {
                closedir(d);
                return -1;
            }
        }
    }

    closedir(d);
    return 0;
}




// send file for relpath = "file" or "dir/file"
static int util_handle_get(SSL *ssl, const char *relpath) {
    if (!util_safe_relpath(relpath)) {
        const char *msg = "ERR NAME\n";
        return util_send_all_ssl(ssl, msg, strlen(msg));
    }
    char path[PATH_MAX];
    snprintf(path, sizeof path, "%s/%s", ROOT_DIR, relpath);

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        const char *msg = "ERR NOFILE\n";
        return util_send_all_ssl(ssl, msg, strlen(msg));
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        const char *msg = "ERR STAT\n";
        return util_send_all_ssl(ssl, msg, strlen(msg));
    }

    char hdr[MAX_LINE];
    snprintf(hdr, sizeof hdr, "OK %lld\n", (long long)st.st_size);
    if (util_send_all_ssl(ssl, hdr, strlen(hdr)) != 0) { close(fd); return -1; }

    char buf[BUF_SZ];
    ssize_t n;
    while ((n = read(fd, buf, sizeof buf)) > 0) {
        if (util_send_all_ssl(ssl, buf, (size_t)n) != 0) { close(fd); return -1; }
    }
    close(fd);
    return (n < 0) ? -1 : 0;
}
