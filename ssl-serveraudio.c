/**
 * @file ssl-serveraudio.c
 * @authors ** Kenneth Sherwood, Thomas Wintenburg, Bradley Spence **
 * @date ** 10/14/2025 **
 * @brief Secure MP3 server for encrypted media distribution.
 * 
 * srms_server.c
 * Simple TLS file server with LIST and GET. Thread-per-connection. 
 */

#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <limits.h>   
#include <dirent.h>   
#include <sys/stat.h> 
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
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

typedef struct {
    int client_fd;
    SSL *ssl;
    struct sockaddr_in addr;
} client_ctx_t;

static void die(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap); va_end(ap);
    fprintf(stderr, "\n");
    exit(EXIT_FAILURE);
}

static void log_msg(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vfprintf(stdout, fmt, ap); va_end(ap);
    fprintf(stdout, "\n"); fflush(stdout);
}


static SSL_CTX *make_ctx(void) {
    const SSL_METHOD *m = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(m);
    if (!ctx) die("SSL_CTX_new failed");

    // Server cert and key
    if (SSL_CTX_use_certificate_file(ctx, CERTIFICATE_FILE, SSL_FILETYPE_PEM) <= 0)
        die("use_certificate_file failed");
    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0)
        die("use_privatekey_file failed");
    if (!SSL_CTX_check_private_key(ctx))
        die("private key mismatch");

    // Optional client auth. Enable later if you decide to use mTLS.
    // SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    // SSL_CTX_load_verify_locations(ctx, "ca.pem", NULL);

    // Prefer TLS 1.3 if available
#ifdef TLS1_3_VERSION
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
#endif
    return ctx;
}

static int listen_on(uint16_t port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) die("socket: %s", strerror(errno));
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = htons(port);
    if (bind(s, (struct sockaddr *)&a, sizeof(a)) < 0)
        die("bind: %s", strerror(errno));
    if (listen(s, 16) < 0)
        die("listen: %s", strerror(errno));
    return s;
}

static bool safe_filename(const char *name) {
    if (!name || !*name) return false;
    if (strstr(name, "..")) return false;
    if (*name == '/' || *name == '\\') return false;
    // only allow basic chars
    for (const char *p = name; *p; ++p) {
        unsigned char c = (unsigned char)*p;
        if (!(c=='-' || c=='_' || c=='.' || (c>='a'&&c<='z') || (c>='A'&&c<='Z') || (c>='0'&&c<='9')))
            return false;
    }
    return true;
}

static ssize_t ssl_readline(SSL *ssl, char *buf, size_t cap) {
    size_t n = 0;
    while (n + 1 < cap) {
        char c;
        int r = SSL_read(ssl, &c, 1);
        if (r <= 0) return (n==0) ? r : (ssize_t)n;
        buf[n++] = c;
        if (c == '\n') break;
    }
    buf[n] = 0;
    // trim CRLF
    while (n && (buf[n-1] == '\n' || buf[n-1] == '\r')) buf[--n] = 0;
    return (ssize_t)n;
}

static int send_all_ssl(SSL *ssl, const void *buf, size_t len) {
    const unsigned char *p = buf;
    while (len) {
        int w = SSL_write(ssl, p, (int)((len > INT_MAX) ? INT_MAX : len));
        if (w <= 0) return -1;
        p += w; len -= w;
    }
    return 0;
}

static int handle_list(SSL *ssl) {
    DIR *d = opendir(ROOT_DIR);
    if (!d) {
        const char *msg = "ERR OPEN\n";
        return send_all_ssl(ssl, msg, strlen(msg));
    }

    // First pass: count regular files using stat()
    size_t count = 0;
    struct dirent *ent;
    while ((ent = readdir(d))) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;

        char path[PATH_MAX];
        snprintf(path, sizeof path, "%s/%s", ROOT_DIR, ent->d_name);

        struct stat st;
        if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) count++;
    }
    rewinddir(d);

    // Send header
    char hdr[MAX_LINE];
    snprintf(hdr, sizeof hdr, "OK %zu\n", count);
    if (send_all_ssl(ssl, hdr, strlen(hdr)) != 0) { closedir(d); return -1; }

    // Second pass: send file names
    while ((ent = readdir(d))) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;

        char path[PATH_MAX];
        snprintf(path, sizeof path, "%s/%s", ROOT_DIR, ent->d_name);

        struct stat st;
        if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
            char line[MAX_LINE];
            snprintf(line, sizeof line, "%s\n", ent->d_name);
            if (send_all_ssl(ssl, line, strlen(line)) != 0) { closedir(d); return -1; }
        }
    }
    closedir(d);
    return 0;
}


static int handle_get(SSL *ssl, const char *fname) {
    if (!safe_filename(fname)) {
        const char *msg = "ERR NAME\n";
        return send_all_ssl(ssl, msg, strlen(msg));
    }
    char path[PATH_MAX];
    snprintf(path, sizeof path, "%s/%s", ROOT_DIR, fname);

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        const char *msg = "ERR NOFILE\n";
        return send_all_ssl(ssl, msg, strlen(msg));
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        const char *msg = "ERR STAT\n";
        return send_all_ssl(ssl, msg, strlen(msg));
    }

    char hdr[MAX_LINE];
    snprintf(hdr, sizeof hdr, "OK %lld\n", (long long)st.st_size);
    if (send_all_ssl(ssl, hdr, strlen(hdr)) != 0) { close(fd); return -1; }

    char buf[BUF_SZ];
    ssize_t n;
    while ((n = read(fd, buf, sizeof buf)) > 0) {
        if (send_all_ssl(ssl, buf, (size_t)n) != 0) { close(fd); return -1; }
    }
    close(fd);
    return (n < 0) ? -1 : 0;
}

static void *serve_one(void *arg) {
    client_ctx_t *c = (client_ctx_t *)arg;
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &c->addr.sin_addr, ip, sizeof ip);
    log_msg("Client connected from %s", ip);

    if (SSL_accept(c->ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        goto done;
    }

    char line[MAX_LINE];
    while (1) {
        ssize_t r = ssl_readline(c->ssl, line, sizeof line);
        if (r <= 0) break;

        // Commands: LIST  |  GET <fname>  |  QUIT
        if (strcmp(line, "LIST") == 0) {
            if (handle_list(c->ssl) != 0) break;
        } else if (strncmp(line, "GET ", 4) == 0) {
            const char *fname = line + 4;
            if (handle_get(c->ssl, fname) != 0) break;
        } else if (strcmp(line, "QUIT") == 0) {
            const char *msg = "OK BYE\n";
            send_all_ssl(c->ssl, msg, strlen(msg));
            break;
        } else {
            const char *msg = "ERR CMD\n";
            if (send_all_ssl(c->ssl, msg, strlen(msg)) != 0) break;
        }
    }

done:
    SSL_shutdown(c->ssl);
    SSL_free(c->ssl);
    close(c->client_fd);
    free(c);
    return NULL;
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);

    int port = (argc >= 2) ? atoi(argv[1]) : DEFAULT_PORT;

    // Ensure media directory exists
    struct stat st;
    if (stat(ROOT_DIR, &st) != 0 || !S_ISDIR(st.st_mode))
        die("Create directory %s and put mp3 files there", ROOT_DIR);

    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    SSL_CTX *ctx = make_ctx();

    int srv = listen_on((uint16_t)port);
    log_msg("Listening on %d. Serving from %s", port, ROOT_DIR);

    while (1) {
        struct sockaddr_in ca; socklen_t clen = sizeof ca;
        int cfd = accept(srv, (struct sockaddr *)&ca, &clen);
        if (cfd < 0) { perror("accept"); continue; }

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, cfd);

        client_ctx_t *cc = calloc(1, sizeof *cc);
        cc->client_fd = cfd; cc->ssl = ssl; cc->addr = ca;

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

    close(srv);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}
