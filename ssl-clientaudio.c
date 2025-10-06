/**
 * @file ssl-serveraudio.c
 * @authors ** Kenneth Sherwood, Thomas Wintenberg, Bradley Spence **
 * @date  ** 10/06/2025 **
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
#define DEFAULT_HOST        "localhost"
#define BUFFER_SIZE         4096
#define OUTPUT_PATH         "downloaded.mp3"

// SSL setup
SSL_CTX* init_ssl_context();
SSL* connect_ssl(SSL_CTX *ctx, const char *hostname, int port);

// MP3 transfer and playback
int request_mp3_file(SSL *ssl, const char *filename, const char *output_path);
int play_mp3(const char *filepath);

// User interaction
void display_genre_menu(char *genre);
void get_search_term(char *term);
void to_lowercase(char *str);

int main() {
    SSL_CTX *ctx = init_ssl_context();
    SSL *ssl = connect_ssl(ctx, DEFAULT_HOST, DEFAULT_PORT);
    printf("Secure connection established.\n");

    char genre[64], term[128], filename[128];

    display_genre_menu(genre);
    get_search_term(term);
    to_lowercase(genre);

    // Send search query
    char query[256];
    snprintf(query, sizeof(query), "SEARCH %s %s\n", genre, term);
    SSL_write(ssl, query, strlen(query));

    // Receive filename
    int bytes = SSL_read(ssl, filename, sizeof(filename) - 1);
    if (bytes <= 0) {
        fprintf(stderr, "No matching file received.\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return 1;
    }
    filename[bytes] = '\0';
    printf("Server found file: %s\n", filename);

    // Request and download file
    if (request_mp3_file(ssl, filename, OUTPUT_PATH) == 0) {
        printf("Download complete. Playing MP3...\n");
        play_mp3(OUTPUT_PATH);
    } else {
        fprintf(stderr, "Download failed.\n");
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}

SSL_CTX* init_ssl_context() {
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

SSL* connect_ssl(SSL_CTX *ctx, const char *hostname, int port) {
    int sock;
    struct sockaddr_in addr;
    SSL *ssl;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(hostname);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ssl;
}

int request_mp3_file(SSL *ssl, const char *filename, const char *output_path) {
    char request[256];
    snprintf(request, sizeof(request), "GET %s\n", filename);
    SSL_write(ssl, request, strlen(request));

    FILE *fp = fopen(output_path, "wb");
    if (!fp) {
        perror("File open failed");
        return -1;
    }

    char buffer[BUFFER_SIZE];
    int bytes;
    while ((bytes = SSL_read(ssl, buffer, sizeof(buffer))) > 0) {
        fwrite(buffer, 1, bytes, fp);
    }

    fclose(fp);
    return 0;
}

int play_mp3(const char *filepath) {
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

void display_genre_menu(char *genre) {
    printf("Select a genre:\n");
    printf("1. Country\n2. Pop\n3. Hip Hop\n4. R&B\n5. Rock\n");
    printf("Enter genre name: ");
    fgets(genre, 64, stdin);
    genre[strcspn(genre, "\n")] = '\0';
}

void get_search_term(char *term) {
    printf("Enter artist name or song title: ");
    fgets(term, 128, stdin);
    term[strcspn(term, "\n")] = '\0';
}

void to_lowercase(char *str) {
    for (int i = 0; str[i]; i++) {
        str[i] = tolower((unsigned char)str[i]);
    }
}
