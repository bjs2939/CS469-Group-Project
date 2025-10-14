/**
 * @file ssl-serveraudio.c
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
#include <netdb.h>
#include <errno.h>
#include <resolv.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <mpg123.h>
#include <portaudio.h>

#define DEFAULT_PORT        4433
#define DEFAULT_HOST        "127.0.0.1"
#define BUFFER_SIZE         4096
#define OUTPUT_PATH         "downloaded.mp3"
#define MAX_FILENAME_LEN    256
#define MAX_FILES           256

// SSL/TLS Functions
SSL_CTX* ssl_init_context();
SSL* ssl_connect(SSL_CTX *ctx, const char *hostname, int port);
static int ssl_readline_simple(SSL *ssl, char *buf, size_t cap);

// MP3 and File Handling Functions
int mp3_request_and_download(SSL *ssl, const char *filename, const char *output_path);
int mp3_play(const char *filepath);
int fetch_file_list(SSL *ssl, char names[][MAX_FILENAME_LEN], int max_names)

// User interaction
void ui_display_genre_menu(char *genre);
void ui_get_search_term(char *term);

// Utility Functions
void util_to_lowercase(char *str);

int main(void) {
    // 1) TLS setup + connect
    SSL_CTX *ctx = init_ssl_context();
    SSL *ssl = ssl_connect(ctx, DEFAULT_HOST, DEFAULT_PORT);
    printf("Secure connection established.\n");

    // 2) Ask server for list of files
    char names[256][256];
    int num = fetch_list(ssl, names, 256);
    if (num <= 0) {
        fprintf(stderr, "No files available or LIST failed.\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return 1;
    }

    // 3) Show numeric menu
    printf("\nAvailable files:\n");
    for (int i = 0; i < num; i++) {
        printf("%d) %s\n", i + 1, names[i]);
    }

    // 4) Read user choice
    printf("Choose a number: ");
    char line[32];
    if (!fgets(line, sizeof(line), stdin)) {
        fprintf(stderr, "Input error.\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return 1;
    }
    int choice = atoi(line);
    if (choice < 1 || choice > num) {
        fprintf(stderr, "Invalid choice.\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return 1;
    }
    const char *filename = names[choice - 1];

    // 5) GET and play
    if (mp3_request_and_download(ssl, filename, OUTPUT_PATH) == 0) {
        printf("Download complete. Playing MP3...\n");
        mp3_play(OUTPUT_PATH);
    } else {
        fprintf(stderr, "Download failed.\n");
    }

    // 6) Clean up TLS
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
} //end main

//--- SSL and TLS ---//
SSL_CTX* ssl_init_context() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (!SSL_CTX_load_verify_locations(ctx, "cert.pem", NULL)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

SSL* ssl_connect(SSL_CTX *ctx, const char *hostname, int port) {
    int sock;
    struct sockaddr_in addr;
    SSL *ssl;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(hostname);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("Connection failed");
        return NULL;
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(sock);
        return NULL;
    }

    return ssl;
}

/**
 * @brief Read a single '\n'-terminated line from SSL, trim CR/LF.
 * @return Number of bytes in line (>=0) or -1 on error/closed.
 */
static int ssl_readline_simple(SSL *ssl, char *buf, size_t cap) {
    size_t n = 0;
    while (n + 1 < cap) {
        char c;
        int r = SSL_read(ssl, &c, 1);
        if (r <= 0) return -1;
        buf[n++] = c;
        if (c == '\n') break;
    }
    buf[n] = 0;
    while (n && (buf[n-1] == '\n' || buf[n-1] == '\r')) {
        buf[--n] = 0;
    }
    return (int)n;
}

//--- MP3 and File Handling --//
int mp3_request_and_download(SSL *ssl, const char *filename, const char *output_path) {
    // Send GET
    char request[256];
    snprintf(request, sizeof(request), "GET %s\n", filename);
    if (SSL_write(ssl, request, (int)strlen(request)) <= 0) {
        fprintf(stderr, "SSL_write GET failed\n");
        return -1;
    }

    // Read header: "OK <size>\n" or "ERR ...\n"
    char hdr[256];
    if (ssl_readline_simple(ssl, hdr, sizeof(hdr)) < 0) {
        fprintf(stderr, "GET header read failed\n");
        return -1;
    }

    long long total = 0;
    if (strncmp(hdr, "OK ", 3) == 0) {
        if (sscanf(hdr + 3, "%lld", &total) != 1 || total < 0) {
            fprintf(stderr, "Bad OK header: %s\n", hdr);
            return -1;
        }
    } else {
        fprintf(stderr, "Server error: %s\n", hdr);
        return -1;
    }

    FILE *fp = fopen(output_path, "wb");
    if (!fp) { perror("File open failed"); return -1; }

    char buf[BUFFER_SIZE];
    long long remaining = total;
    while (remaining > 0) {
        int toread = (remaining > (long long)sizeof(buf)) ? (int)sizeof(buf) : (int)remaining;
        int n = SSL_read(ssl, buf, toread);
        if (n <= 0) { fprintf(stderr, "SSL_read body failed\n"); fclose(fp); return -1; }
        fwrite(buf, 1, (size_t)n, fp);
        remaining -= n;
    }

    fclose(fp);
    return 0;
} //end requestMp3File

int mp3_play(const char *filepath) {
    mpg123_handle *mh;
    unsigned char *audio;
    size_t done;
    int err, channels, encoding;
    long rate;

    PaStream *stream;
    Pa_Initialize();
    mpg123_init();
    mh = mpg123_new(NULL, &err);
    mpg123_open(mh, filepath);
    mpg123_getformat(mh, &rate, &channels, &encoding);

    Pa_OpenDefaultStream(&stream, 0, channels, paInt16, rate, BUFFER_SIZE, NULL, NULL);
    Pa_StartStream(stream);

    audio = malloc(BUFFER_SIZE);
    while (mpg123_read(mh, audio, BUFFER_SIZE, &done) == MPG123_OK) {
        Pa_WriteStream(stream, audio, done / sizeof(short));
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

/**
 * Robust LIST reader: parse "OK <count>\n" then read exactly <count> lines
 * Fetch "OK <count>\n" then read exactly <count> filenames (one per line).
 * 
 * @brief Fetches a list of files from the server.
 * @return The number of files received, or -1 on error.
 */
int fetch_file_list(SSL *ssl, char names[][MAX_FILENAME_LEN], int max_names) {
    // Ask server
    if (SSL_write(ssl, "LIST\n", 5) <= 0) {
        fprintf(stderr, "SSL_write LIST failed\n");
        return -1;
    }

    // Read header line
    char line[1024];
    if (ssl_readline_simple(ssl, line, sizeof(line)) < 0) {
        fprintf(stderr, "LIST header read failed\n");
        return -1;
    }

    int count = -1;
    if (sscanf(line, "OK %d", &count) != 1 || count < 0) {
        fprintf(stderr, "Bad LIST header: %s\n", line);
        return -1;
    }
    if (count == 0) return 0;

    // Read exactly 'count' filenames
    int received_count = 0;
    for (; received_count < count && received_count < max_names; ++received_count) {
        if (ssl_readline_simple(ssl, line, sizeof(line)) < 0) {
            fprintf(stderr, "LIST body read failed after %d entries\n", received_count);
            return -1;
        }        
        // empty line ends early
        if (line[0] == 0) break;

        // Copy name, clamp to 255
        size_t len = strlen(line);
        if (len > 255) len = 255;
        memcpy(names[received_count], line, len);
        names[received_count][len] = 0;
    }
    return received_count;
} //end fetch

//--- User Interface and Interaction ---//
void ui_display_genre_menu(char *genre) {
    printf("Select a genre:\n");
    printf("1. Country\n2. Pop\n3. Hip Hop\n4. R&B\n5. Rock\n");
    printf("Enter genre name: ");
    fgets(genre, 64, stdin);
    genre[strcspn(genre, "\n")] = '\0';
}

void ui_get_search_term(char *term) {
    printf("Enter artist name or song title: ");
    fgets(term, 128, stdin);
    term[strcspn(term, "\n")] = '\0';
}

//--- Utility Functions ---//
void util_to_lowercase(char *str) {
    for (int i = 0; str[i]; i++) {
        str[i] = tolower((unsigned char)str[i]);
    }
}
