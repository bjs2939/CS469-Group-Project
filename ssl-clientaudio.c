/**
 * @file ssl-clientaudio.c
 * @authors ** Kenneth Sherwood, Thomas Wintenburg, Bradley Spence **
 * @date ** 10/14/2025 **
 * @brief Secure MP3 server for encrypted media distribution and process replication.
 *
 * This program implements the server component of a distributed MP3 media system.
 * It provides secure file listing and download functionality for authenticated clients
 * over SSL/TLS using OpenSSL. All network communications are encrypted to ensure
 * confidentiality and integrity of transmitted audio data.
 *
 * The server runs in a POSIX environment, supports concurrent connections using threads,
 * and can be replicated across multiple instances for fault tolerance. Clients connect
 * to the server to request available MP3 files, which are transmitted in binary-safe
 * chunks over the encrypted channel.
 *
 * Each server instance uses X.509 certificates for authentication and session encryption.
 * The program can be configured to operate on multiple ports to demonstrate distribution
 * transparency and failover recovery.
 *
 * Some code and descriptions are adapted from "Network Security with OpenSSL",
 * O'Reilly Media, 2002.
 */




#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <mpg123.h>
#include <portaudio.h>

#define DEFAULT_HOST  "127.0.0.1"
#define DEFAULT_PORT  4433
#define BUFFER_SIZE   4096
#define MAX_NAME      256
#define MAX_LIST      256

#ifndef ENABLE_AUDIO
#define ENABLE_AUDIO 1
#endif

// debug macro: always prints 
#define SCRIPT_NAME "ssl-clientaudio.c"
#define DBG(fn, fmt, ...) \
    do { \
        printf("[" SCRIPT_NAME "] - [function %s] - " fmt "\n", fn, ##__VA_ARGS__); \
        fflush(stdout); \
        


// fwd decls 
// tls
static SSL_CTX* ssl_init_context(void);
static SSL*     ssl_connect_to(SSL_CTX *ctx, const char *host, int port);
static int      ssl_readline(SSL *ssl, char *buf, size_t cap);

// protocol
static int fetch_dir_list(SSL *ssl, char names[][MAX_NAME], int max);
static int fetch_file_list_in_dir(SSL *ssl, const char *dirname, char names[][MAX_NAME], int max);
static int get_file(SSL *ssl, const char *relpath, const char *outpath);

// ui
static int  ui_pick(const char *title, char items[][MAX_NAME], int n);
static void trim_eol(char *s);

// helpers
static int  is_digits(const char *s);
static void sanitize(char *s);
static void make_outpath_for_port(int port, const char *folder, const char *file, char *out, size_t cap);

#if ENABLE_AUDIO
static int mp3_play(const char *filepath);
#endif



// helpers 

static int is_digits(const char *s) {
    if (!s || !*s) return 0;
    for (const unsigned char *p = (const unsigned char*)s; *p; ++p)
        if (*p < '0' || *p > '9') return 0;
    return 1;
}

// replace unsafe chars for filenames 
static void sanitize(char *s) {
    for (char *p = s; *p; ++p) {
        if (*p=='/'||*p=='\\'||*p==':'||*p=='*'||*p=='?'||*p=='"'||*p=='<'||*p=='>'||*p=='|')
            *p = '_';
    }
}



// build unique output path so clients do not clobber each other 
static void make_outpath_for_port(int port, const char *folder, const char *file,
                                  char *out, size_t cap) {
    char f1[MAX_NAME], f2[MAX_NAME];
    snprintf(f1, sizeof f1, "%s", folder);
    snprintf(f2, sizeof f2, "%s", file);
    sanitize(f1);
    sanitize(f2);
    mkdir("downloads", 0777);
    pid_t pid = getpid();
    snprintf(out, cap, "downloads/%d__%ld__%s__%s.mp3",
             port, (long)pid, f1, f2);
}




// main 
int main(int argc, char **argv) {
    const char *host = DEFAULT_HOST;
    int port = DEFAULT_PORT;
    int do_play = 1;

    DBG("main", "start client");

    // parse args: <port> or <host> <port> plus flags 
    if (argc >= 2 && argv[1][0] != '-') {
        if (is_digits(argv[1])) {
            port = atoi(argv[1]); // number -> port 
        } else {
            host = argv[1];       // string -> host 
            if (argc >= 3 && is_digits(argv[2])) port = atoi(argv[2]);
        }
    }
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--no-play") == 0) do_play = 0;
    }

    DBG("main", "config host=%s port=%d do_play=%d", host, port, do_play);

    // tls ctx 
    SSL_CTX *ctx = ssl_init_context();
    if (!ctx) {
        fprintf(stderr, "[" SCRIPT_NAME "] - [function main] - ssl ctx init failed\n");
        return 1;
    }

    // connect 
    SSL *ssl = ssl_connect_to(ctx, host, port);
    if (!ssl) {
        fprintf(stderr, "[" SCRIPT_NAME "] - [function main] - tls connect failed\n");
        SSL_CTX_free(ctx);
        return 1;
    }
    DBG("main", "secure connection established to %s:%d", host, port);

    // list folders 
    char dirs[MAX_LIST][MAX_NAME];
    int ndirs = fetch_dir_list(ssl, dirs, MAX_LIST);
    if (ndirs <= 0) {
        fprintf(stderr, "[" SCRIPT_NAME "] - [function main] - folders list failed or empty\n");
        goto done;
    }
    int di = ui_pick("folders", dirs, ndirs);
    if (di < 0) goto done;
    const char *folder = dirs[di];
    DBG("main", "picked folder=%s", folder);

    // list files in folder 
    char files[MAX_LIST][MAX_NAME];
    int nfiles = fetch_file_list_in_dir(ssl, folder, files, MAX_LIST);
    if (nfiles <= 0) {
        fprintf(stderr, "[" SCRIPT_NAME "] - [function main] - files list failed or empty\n");
        goto done;
    }
    int fi = ui_pick("files", files, nfiles);
    if (fi < 0) goto done;
    const char *file = files[fi];
    DBG("main", "picked file=%s", file);

    // build relpath and output path 
    char relpath[2*MAX_NAME + 8];
    snprintf(relpath, sizeof relpath, "%s/%s", folder, file);

    char outpath[1024];
    make_outpath_for_port(port, folder, file, outpath, sizeof outpath);

    DBG("main", "request relpath=%s out=%s", relpath, outpath);

    // download 
    if (get_file(ssl, relpath, outpath) == 0) {
        DBG("main", "download complete -> %s", outpath);
#if ENABLE_AUDIO
        if (do_play) {
            DBG("main", "playing mp3 -> %s", outpath);
            if (mp3_play(outpath) != 0) {
                fprintf(stderr, "[" SCRIPT_NAME "] - [function main] - playback failed (check audio)\n");
            }
        }
#endif
    } else {
        fprintf(stderr, "[" SCRIPT_NAME "] - [function main] - download failed\n");
    }

done:
    DBG("main", "shutdown");
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}

// tls helpers 

static SSL_CTX* ssl_init_context(void) {
    DBG("ssl_init_context", "init openssl libs");
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    // trust server cert from local cert.pem 
    if (!SSL_CTX_load_verify_locations(ctx, "cert.pem", NULL)) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    DBG("ssl_init_context", "ctx ready");
    return ctx;
}

static SSL* ssl_connect_to(SSL_CTX *ctx, const char *host, int port) {
    DBG("ssl_connect_to", "connecting to %s:%d", host, port);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return NULL;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        fprintf(stderr, "[" SCRIPT_NAME "] - [function ssl_connect_to] - bad host ip: %s\n", host);
        close(sock);
        return NULL;
    }

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("connect");
        close(sock);
        return NULL;
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sock);
        return NULL;
    }

    DBG("ssl_connect_to", "tls handshake ok");
    return ssl;
}

static int ssl_readline(SSL *ssl, char *buf, size_t cap) {
    // read to newline, trim crlf 
    size_t n = 0;
    while (n + 1 < cap) {
        char c;
        int r = SSL_read(ssl, &c, 1);
        if (r <= 0) {
            int err = SSL_get_error(ssl, r);
            fprintf(stderr, "[" SCRIPT_NAME "] - [function ssl_readline] - r=%d err=%d\n", r, err);
            return (n == 0) ? -1 : (int)n;
        }
        buf[n++] = c;
        if (c == '\n') break;
    }
    buf[n] = 0;
    while (n && (buf[n-1]=='\n' || buf[n-1]=='\r')) buf[--n] = 0;
    DBG("ssl_readline", "got line='%s'", buf);
    return (int)n;
}


static int fetch_dir_list(SSL *ssl, char names[][MAX_NAME], int max) {
    DBG("fetch_dir_list", "send LISTDIR");
    int w = SSL_write(ssl, "LISTDIR\n", 8);
    if (w <= 0) {
        int err = SSL_get_error(ssl, w);
        fprintf(stderr, "[" SCRIPT_NAME "] - [function fetch_dir_list] - write fail err=%d\n", err);
        return -1;
    }

    char line[1024];
    int r = ssl_readline(ssl, line, sizeof line);
    if (r < 0) {
        fprintf(stderr, "[" SCRIPT_NAME "] - [function fetch_dir_list] - header read fail\n");
        return -1;
    }

    int count = 0;
    if (sscanf(line, "OK %d", &count) != 1 || count < 0) {
        fprintf(stderr, "[" SCRIPT_NAME "] - [function fetch_dir_list] - bad hdr, want 'OK <n>' got '%s'\n", line);
        return -1;
    }
    DBG("fetch_dir_list", "count=%d", count);

    int got = 0;
    while (got < count && got < max) {
        int rr = ssl_readline(ssl, line, sizeof line);
        if (rr < 0) {
            fprintf(stderr, "[" SCRIPT_NAME "] - [function fetch_dir_list] - body read fail @%d\n", got);
            return -1;
        }
        if (!line[0]) break;
        size_t len = strlen(line);
        if (len >= MAX_NAME) len = MAX_NAME - 1;
        memcpy(names[got], line, len);
        names[got][len] = 0;
        DBG("fetch_dir_list", "dir[%d]=%s", got, names[got]);
        got++;
    }
    return got;
}

static int fetch_file_list_in_dir(SSL *ssl, const char *dirname, char names[][MAX_NAME], int max) {
    DBG("fetch_file_list_in_dir", "send LIST %s", dirname);

    char cmd[512];
    snprintf(cmd, sizeof cmd, "LIST %s\n", dirname);
    if (SSL_write(ssl, cmd, (int)strlen(cmd)) <= 0) {
        fprintf(stderr, "[" SCRIPT_NAME "] - [function fetch_file_list_in_dir] - write fail\n");
        return -1;
    }

    char line[1024];
    if (ssl_readline(ssl, line, sizeof line) < 0) {
        fprintf(stderr, "[" SCRIPT_NAME "] - [function fetch_file_list_in_dir] - hdr read fail\n");
        return -1;
    }

    int count = 0;
    if (sscanf(line, "OK %d", &count) != 1 || count < 0) {
        fprintf(stderr, "[" SCRIPT_NAME "] - [function fetch_file_list_in_dir] - bad hdr '%s'\n", line);
        return -1;
    }
    DBG("fetch_file_list_in_dir", "count=%d", count);

    int got = 0;
    while (got < count && got < max) {
        if (ssl_readline(ssl, line, sizeof line) < 0) {
            fprintf(stderr, "[" SCRIPT_NAME "] - [function fetch_file_list_in_dir] - body read fail @%d\n", got);
            return -1;
        }
        if (!line[0]) break;
        size_t len = strlen(line);
        if (len >= MAX_NAME) len = MAX_NAME - 1;
        memcpy(names[got], line, len);
        names[got][len] = 0;
        DBG("fetch_file_list_in_dir", "file[%d]=%s", got, names[got]);
        got++;
    }
    return got;
}

// download 1 file 
static int get_file(SSL *ssl, const char *relpath, const char *outpath) {
    DBG("get_file", "start relpath=%s out=%s", relpath, outpath);

    // send GET relpath\n 
    if (SSL_write(ssl, "GET ", 4) <= 0) {
        fprintf(stderr, "[" SCRIPT_NAME "] - [function get_file] - write 'GET ' failed\n");
        return -1;
    }
    size_t len = strlen(relpath);
    if (len == 0) {
        fprintf(stderr, "[" SCRIPT_NAME "] - [function get_file] - empty relpath\n");
        return -1;
    }
    if (SSL_write(ssl, relpath, (int)len) <= 0) {
        fprintf(stderr, "[" SCRIPT_NAME "] - [function get_file] - write relpath failed\n");
        return -1;
    }
    if (SSL_write(ssl, "\n", 1) <= 0) {
        fprintf(stderr, "[" SCRIPT_NAME "] - [function get_file] - write newline failed\n");
        return -1;
    }

    // read header 
    char hdr[256];
    if (ssl_readline(ssl, hdr, sizeof hdr) < 0) {
        fprintf(stderr, "[" SCRIPT_NAME "] - [function get_file] - hdr read failed\n");
        return -1;
    }
    DBG("get_file", "hdr='%s'", hdr);

    long long total = 0;
    if (strncmp(hdr, "OK ", 3) == 0) {
        if (sscanf(hdr + 3, "%lld", &total) != 1 || total < 0) {
            fprintf(stderr, "[" SCRIPT_NAME "] - [function get_file] - bad OK hdr '%s'\n", hdr);
            return -1;
        }
    } else {
        fprintf(stderr, "[" SCRIPT_NAME "] - [function get_file] - server error '%s'\n", hdr);
        return -1;
    }

    // open file exclusively 
    int fd = open(outpath, O_WRONLY | O_CREAT | O_EXCL, 0666);
    if (fd < 0) {
        perror("open");
        return -1;
    }
    FILE *fp = fdopen(fd, "wb");
    if (!fp) {
        perror("fdopen");
        close(fd);
        return -1;
    }
    DBG("get_file", "writing size=%lld to %s", total, outpath);

    // read loop 
    char buf[BUFFER_SIZE];
    long long remaining = total;
    while (remaining > 0) {
        int want = (remaining > (long long)sizeof(buf)) ? (int)sizeof(buf) : (int)remaining;
        int n = SSL_read(ssl, buf, want);
        if (n <= 0) {
            fprintf(stderr, "[" SCRIPT_NAME "] - [function get_file] - body read fail\n");
            fclose(fp);
            return -1;
        }
        if (fwrite(buf, 1, (size_t)n, fp) != (size_t)n) {
            perror("fwrite");
            fclose(fp);
            return -1;
        }
        remaining -= n;
    }

    fclose(fp);
    DBG("get_file", "download complete -> %s", outpath);
    return 0;
}

// ui 

static void trim_eol(char *s) {
    size_t n = strlen(s);
    while (n && (s[n-1]=='\n' || s[n-1]=='\r')) s[--n] = 0;
}

static int ui_pick(const char *title, char items[][MAX_NAME], int n) {
    printf("\n%s:\n", title);
    for (int i = 0; i < n; ++i) printf("%d) %s\n", i + 1, items[i]);
    printf("choose a number: ");
    char line[64];
    if (!fgets(line, sizeof line, stdin)) return -1;
    trim_eol(line);
    int choice = atoi(line);
    if (choice < 1 || choice > n) {
        fprintf(stderr, "[" SCRIPT_NAME "] - [function ui_pick] - invalid choice\n");
        return -1;
    }
    DBG("ui_pick", "picked %d -> %s", choice, items[choice - 1]);
    return choice - 1;
}

// audio 

#if ENABLE_AUDIO
static int mp3_play(const char *filepath) {
    DBG("mp3_play", "start file=%s", filepath);

    mpg123_handle *mh = NULL;
    unsigned char *audio = NULL;
    size_t done = 0;
    int err = 0, channels = 0, encoding = 0;
    long rate = 0;
    PaStream *stream = NULL;

    if (Pa_Initialize() != paNoError) {
        fprintf(stderr, "[" SCRIPT_NAME "] - [function mp3_play] - pa init fail\n");
        return -1;
    }
    mpg123_init();
    mh = mpg123_new(NULL, &err);
    if (!mh) {
        Pa_Terminate();
        fprintf(stderr, "[" SCRIPT_NAME "] - [function mp3_play] - mpg123 new fail\n");
        return -1;
    }

    if (mpg123_open(mh, filepath) != MPG123_OK) {
        mpg123_delete(mh);
        Pa_Terminate();
        fprintf(stderr, "[" SCRIPT_NAME "] - [function mp3_play] - open fail\n");
        return -1;
    }
    mpg123_getformat(mh, &rate, &channels, &encoding);

    if (Pa_OpenDefaultStream(&stream, 0, channels, paInt16, rate, BUFFER_SIZE, NULL, NULL) != paNoError) {
        mpg123_close(mh);
        mpg123_delete(mh);
        Pa_Terminate();
        fprintf(stderr, "[" SCRIPT_NAME "] - [function mp3_play] - open stream fail\n");
        return -1;
    }
    Pa_StartStream(stream);

    audio = (unsigned char*)malloc(BUFFER_SIZE);
    if (!audio) {
        Pa_StopStream(stream);
        Pa_CloseStream(stream);
        mpg123_close(mh);
        mpg123_delete(mh);
        Pa_Terminate();
        fprintf(stderr, "[" SCRIPT_NAME "] - [function mp3_play] - malloc fail\n");
        return -1;
    }

    while (mpg123_read(mh, audio, BUFFER_SIZE, &done) == MPG123_OK) {
        Pa_WriteStream(stream, audio, (unsigned long)(done / sizeof(short)));
    }

    free(audio);
    Pa_StopStream(stream);
    Pa_CloseStream(stream);
    Pa_Terminate();
    mpg123_close(mh);
    mpg123_delete(mh);
    mpg123_exit();
    DBG("mp3_play", "done");
    return 0;
}
#endif
