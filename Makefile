# Makefile

CC := gcc
UNAME := $(shell uname)

CLIENT_SRC := ssl-clientaudio.c
SERVER_SRC := ssl-serveraudio.c

OPENSSL_LIBDIR ?= /usr/lib/x86_64-linux-gnu

CFLAGS   += -O2 -Wall
LDFLAGS  += -L$(OPENSSL_LIBDIR)

ifeq ($(UNAME),Darwin)
CFLAGS  += -I/usr/local/opt/openssl/include
LDFLAGS += -L/usr/local/opt/openssl/lib
endif

# client: dynamic (audio libs usually dynamic)
CLIENT_LIBS := -lssl -lcrypto -lmpg123 -lportaudio -lm -lpthread

# server: dynamic by default (so it builds everywhere)
SERVER_LIBS := -lssl -lcrypto -lpthread -ldl

# make STATIC_SSL=1 -> try static ssl/crypto (glibc still dynamic)
ifeq ($(STATIC_SSL),1)
SERVER_LIBS := -Wl,-Bstatic -l:libssl.a -l:libcrypto.a -Wl,-Bdynamic -lpthread -ldl
endif

# make FULL_STATIC=1 -> try fully static (often fails on glibc)
ifeq ($(FULL_STATIC),1)
SERVER_LIBS := -static -l:libssl.a -l:libcrypto.a -lpthread -ldl
endif

.PHONY: all clean
all: ssl-clientaudio ssl-serveraudio

ssl-clientaudio: $(CLIENT_SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(CLIENT_LIBS)

ssl-serveraudio: $(SERVER_SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(SERVER_LIBS)

clean:
	rm -f ssl-clientaudio ssl-serveraudio *.o
