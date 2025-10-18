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

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <mpg123.h>
#include <portaudio.h>

#define DEFAULT_HOST        "127.0.0.1"
#define DEFAULT_PORT        4433
#define BUFFER_SIZE         4096
#define OUTPUT_PATH         "downloaded.mp3"
#define MAX_NAME            256
#define MAX_LIST            256

// flip to 0 if you want to compile without audio code at all
#ifndef ENABLE_AUDIO
#define ENABLE_AUDIO 1
#endif

// --- tls helpers ---
static SSL_CTX* ssl_init_context(void);
static SSL* ssl_connect_to(SSL_CTX *ctx, const char *host, int port);
static int ssl_readline(SSL *ssl, char *buf, size_t cap);

// --- protocol helpers ---
static int fetch_dir_list(SSL *ssl, char names[][MAX_NAME], int max);
static int fetch_file_list_in_dir(SSL *ssl, const char *dirname, char names[][MAX_NAME], int max);
static int get_file(SSL *ssl, const char *relpath, const char *outpath);

// --- ui helpers ---
static int ui_pick(const char *title, char items[][MAX_NAME], int n);
static void trim_eol(char *s);

// --- audio ---
#if ENABLE_AUDIO
static int mp3_play(const char *filepath);
#endif

int main(int argc, char **argv) {
    // parse args: host port [--no-play]
    const char *host = (argc >= 2 && argv[1][0] != '-') ? argv[1] : DEFAULT_HOST;
    int argi = (argc >= 2 && argv[1][0] != '-') ? 2 : 1;

    int port = DEFAULT_PORT;
    if (argi < argc && argv[argi][0] != '-') { port = atoi(argv[argi]); argi++; }

    int do_play = 1;
    for (; argi < argc; ++argi) {
        if (strcmp(argv[argi], "--no-play") == 0) do_play = 0;
    }

    SSL_CTX *ctx = ssl_init_context();
    SSL *ssl = ssl_connect_to(ctx, host, port);
    if (!ssl) { fprintf(stderr, "tls connect failed\n"); SSL_CTX_free(ctx); return 1; }
    printf("secure connection established.\n");

    // 1) get folders
    char dirs[MAX_LIST][MAX_NAME];
    int ndirs = fetch_dir_list(ssl, dirs, MAX_LIST);
    if (ndirs <= 0) { fprintf(stderr, "no folders or LISTDIR failed.\n"); goto done; }

    int di = ui_pick("folders", dirs, ndirs);
    if (di < 0) goto done;
    const char *folder = dirs[di];

    // 2) get files for folder
    char files[MAX_LIST][MAX_NAME];
    int nfiles = fetch_file_list_in_dir(ssl, folder, files, MAX_LIST);
    if (nfiles <= 0) { fprintf(stderr, "no files in folder or LIST failed.\n"); goto done; }

    int fi = ui_pick("files", files, nfiles);
    if (fi < 0) goto done;
    const char *file = files[fi];

    // 3) request GET folder/file
    char relpath[2*MAX_NAME + 8];
    snprintf(relpath, sizeof relpath, "%s/%s", folder, file);

    if (get_file(ssl, relpath, OUTPUT_PATH) == 0) {
        printf("download complete -> %s\n", OUTPUT_PATH);
#if ENABLE_AUDIO
        if (do_play) {
            printf("playing mp3...\n");
            if (mp3_play(OUTPUT_PATH) != 0) {
                fprintf(stderr, "playback failed (check audio in wsl)\n");
            }
        }
#else
        (void)do_play;
#endif
    } else {
        fprintf(stderr, "download failed.\n");
    }

done:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}

// --- tls helpers ---

static SSL_CTX* ssl_init_context(void) {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) { ERR_print_errors_fp(stderr); exit(EXIT_FAILURE); }
    // trust server cert from cert.pem (same dir)
    if (!SSL_CTX_load_verify_locations(ctx, "cert.pem", NULL)) {
        ERR_print_errors_fp(stderr); exit(EXIT_FAILURE);
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    return ctx;
}

static SSL* ssl_connect_to(SSL_CTX *ctx, const char *host, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); return NULL; }

    struct sockaddr_in addr; memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(host);
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
    return ssl;
}

static int ssl_readline(SSL *ssl, char *buf, size_t cap) {
    size_t n = 0;
    while (n + 1 < cap) {
        char c;
        int r = SSL_read(ssl, &c, 1);
        if (r <= 0) {
            int err = SSL_get_error(ssl, r);
            fprintf(stderr, "[client:ssl_readline] r=%d err=%d (0=none,2=wantread,3=wantwrite,5=SYSCALL,6=SSL)\n", r, err);
            return (n==0) ? -1 : (int)n;
        }
        buf[n++] = c;
        if (c == '\n') break;
    }
    buf[n] = 0;
    while (n && (buf[n-1]=='\n' || buf[n-1]=='\r')) buf[--n] = 0;
    return (int)n;
}

// --- protocol helpers ---

static int fetch_dir_list(SSL *ssl, char names[][MAX_NAME], int max) {
    fprintf(stderr,"[client:fetch_dir_list] sending 'LISTDIR\\n'\n");
    int w1 = SSL_write(ssl, "LISTDIR\n", 8);
    if (w1 <= 0) {
        int err = SSL_get_error(ssl, w1);
        fprintf(stderr,"[client:fetch_dir_list] SSL_write fail w1=%d err=%d\n", w1, err);
        return -1;
    }

    char line[1024];
    int r = ssl_readline(ssl, line, sizeof line);
    if (r < 0) { fprintf(stderr,"[client:fetch_dir_list] header read fail\n"); return -1; }
    fprintf(stderr,"[client:fetch_dir_list] hdr='%s'\n", line);

    int count = 0;
    if (sscanf(line, "OK %d", &count) != 1 || count < 0) {
        fprintf(stderr,"[client:fetch_dir_list] bad hdr (expected 'OK <n>')\n");
        return -1;
    }
    fprintf(stderr,"[client:fetch_dir_list] count=%d\n", count);

    int got = 0;
    while (got < count && got < max) {
        int rr = ssl_readline(ssl, line, sizeof line);
        if (rr < 0) { fprintf(stderr,"[client:fetch_dir_list] body read fail @%d\n", got); return -1; }
        if (!line[0]) break;
        size_t len = strlen(line); if (len >= MAX_NAME) len = MAX_NAME - 1;
        memcpy(names[got], line, len); names[got][len] = 0;
        fprintf(stderr,"[client:fetch_dir_list] dir[%d]=%s\n", got, names[got]);
        got++;
    }
    return got;
}




static int fetch_file_list_in_dir(SSL *ssl, const char *dirname, char names[][MAX_NAME], int max) {
    char cmd[512];
    snprintf(cmd, sizeof cmd, "LIST %s\n", dirname);
    if (SSL_write(ssl, cmd, (int)strlen(cmd)) <= 0) return -1;

    char line[1024];
    if (ssl_readline(ssl, line, sizeof line) < 0) return -1;

    int count = 0;
    if (sscanf(line, "OK %d", &count) != 1 || count < 0) return -1;

    int got = 0;
    while (got < count && got < max) {
        if (ssl_readline(ssl, line, sizeof line) < 0) return -1;
        if (!line[0]) break;
        size_t len = strlen(line); if (len >= MAX_NAME) len = MAX_NAME - 1;
        memcpy(names[got], line, len); names[got][len] = 0;
        got++;
    }
    return got;
}


// get_file: downloads one file from server
static int get_file(SSL *ssl, const char *relpath, const char *outpath) {
    printf("[ssl-clientaudio.c:get_file] start relpath=%s -> %s\n", relpath, outpath);

    // send "GET " + relpath + "\n" safely
    printf("[ssl-clientaudio.c:get_file] sending GET request\n");
    if (SSL_write(ssl, "GET ", 4) <= 0) {
        fprintf(stderr, "[ssl-clientaudio.c:get_file] SSL_write GET prefix failed\n");
        return -1;
    }

    size_t len = strlen(relpath);
    if (len == 0) {
        fprintf(stderr, "[ssl-clientaudio.c:get_file] empty relpath\n");
        return -1;
    }

    if (SSL_write(ssl, relpath, (int)len) <= 0) {
        fprintf(stderr, "[ssl-clientaudio.c:get_file] SSL_write relpath failed\n");
        return -1;
    }

    if (SSL_write(ssl, "\n", 1) <= 0) {
        fprintf(stderr, "[ssl-clientaudio.c:get_file] SSL_write newline failed\n");
        return -1;
    }

    // read header
    printf("[ssl-clientaudio.c:get_file] waiting for header...\n");
    char hdr[256];
    if (ssl_readline(ssl, hdr, sizeof hdr) < 0) {
        fprintf(stderr, "[ssl-clientaudio.c:get_file] GET header read failed\n");
        return -1;
    }
    printf("[ssl-clientaudio.c:get_file] header: %s\n", hdr);

    long long total = 0;
    if (strncmp(hdr, "OK ", 3) == 0) {
        if (sscanf(hdr + 3, "%lld", &total) != 1 || total < 0) {
            fprintf(stderr, "[ssl-clientaudio.c:get_file] bad OK header: %s\n", hdr);
            return -1;
        }
    } else {
        fprintf(stderr, "[ssl-clientaudio.c:get_file] server error: %s\n", hdr);
        return -1;
    }

    // open file
    printf("[ssl-clientaudio.c:get_file] opening output file: %s (size=%lld)\n", outpath, total);
    FILE *fp = fopen(outpath, "wb");
    if (!fp) {
        perror("[ssl-clientaudio.c:get_file] fopen failed");
        return -1;
    }

    // download loop
    char buf[BUFFER_SIZE];
    long long remaining = total;
    while (remaining > 0) {
        int want = (remaining > (long long)sizeof(buf)) ? (int)sizeof(buf) : (int)remaining;
        int n = SSL_read(ssl, buf, want);
        if (n <= 0) {
            fprintf(stderr, "[ssl-clientaudio.c:get_file] SSL_read body failed\n");
            fclose(fp);
            return -1;
        }
        fwrite(buf, 1, (size_t)n, fp);
        remaining -= n;
        printf("[ssl-clientaudio.c:get_file] wrote %d bytes, %lld left\n", n, remaining);
    }

    fclose(fp);
    printf("[ssl-clientaudio.c:get_file] download complete -> %s\n", outpath);
    return 0;
}


// --- ui helpers ---

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
    if (choice < 1 || choice > n) { fprintf(stderr, "invalid choice.\n"); return -1; }
    return choice - 1;
}

// --- audio ---

#if ENABLE_AUDIO
static int mp3_play(const char *filepath) {
    mpg123_handle *mh = NULL;
    unsigned char *audio = NULL;
    size_t done = 0;
    int err = 0, channels = 0, encoding = 0;
    long rate = 0;
    PaStream *stream = NULL;

    if (Pa_Initialize() != paNoError) return -1;
    mpg123_init();
    mh = mpg123_new(NULL, &err);
    if (!mh) { Pa_Terminate(); return -1; }

    if (mpg123_open(mh, filepath) != MPG123_OK) { mpg123_delete(mh); Pa_Terminate(); return -1; }
    mpg123_getformat(mh, &rate, &channels, &encoding);

    if (Pa_OpenDefaultStream(&stream, 0, channels, paInt16, rate, BUFFER_SIZE, NULL, NULL) != paNoError) {
        mpg123_close(mh); mpg123_delete(mh); Pa_Terminate(); return -1;
    }
    Pa_StartStream(stream);

    audio = (unsigned char*)malloc(BUFFER_SIZE);
    if (!audio) { Pa_StopStream(stream); Pa_CloseStream(stream); mpg123_close(mh); mpg123_delete(mh); Pa_Terminate(); return -1; }

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
    return 0;
}
#endif
