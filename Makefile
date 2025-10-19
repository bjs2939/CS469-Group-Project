# Makefile

CC := gcc
UNAME := $(shell uname)

CLIENT_SRC := ssl-clientaudio.c
SERVER_SRC := ssl-serveraudio.c

CFLAGS   ?= -O2 -Wall
LDFLAGS  ?=

OPENSSL_LIBDIR ?= /usr/lib/x86_64-linux-gnu
AUDIO_LIBDIR   ?= /usr/lib/x86_64-linux-gnu

# default: attempt static on both
# set DYNAMIC=1 to force fully dynamic on both
DYNAMIC ?= 0

# search paths
CFLAGS  += -I$(OPENSSL_LIBDIR)/include
LDFLAGS += -L$(OPENSSL_LIBDIR) -L$(AUDIO_LIBDIR)

ifeq ($(UNAME),Darwin)
CFLAGS  += -I/usr/local/opt/openssl/include
LDFLAGS += -L/usr/local/opt/openssl/lib
endif

# detect static archives
HAVE_STATIC_SSL        := $(wildcard $(OPENSSL_LIBDIR)/libssl.a)
HAVE_STATIC_CRYPTO     := $(wildcard $(OPENSSL_LIBDIR)/libcrypto.a)
HAVE_STATIC_MPG123     := $(wildcard $(AUDIO_LIBDIR)/libmpg123.a)
HAVE_STATIC_PORTAUDIO  := $(wildcard $(AUDIO_LIBDIR)/libportaudio.a)

# ------------------------------
# client link flags
CLIENT_LIBS_STATIC := \
  -Wl,-Bstatic -l:libssl.a -l:libcrypto.a -l:libmpg123.a -l:libportaudio.a \
  -Wl,-Bdynamic -lm -lpthread -ldl

CLIENT_LIBS_DYNAMIC := -lssl -lcrypto -lmpg123 -lportaudio -lm -lpthread

# choose client libs
ifeq ($(DYNAMIC),1)
  CLIENT_LIBS := $(CLIENT_LIBS_DYNAMIC)
else
  ifneq ($(and $(HAVE_STATIC_SSL),$(HAVE_STATIC_CRYPTO),$(HAVE_STATIC_MPG123),$(HAVE_STATIC_PORTAUDIO)),)
    CLIENT_LIBS := $(CLIENT_LIBS_STATIC)
  else
    $(warning static audio archives not found. linking client dynamically.)
    CLIENT_LIBS := $(CLIENT_LIBS_DYNAMIC)
  endif
endif

# ------------------------------
# server link flags
SERVER_LIBS_STATIC := \
  -Wl,-Bstatic -l:libssl.a -l:libcrypto.a \
  -Wl,-Bdynamic -lpthread -ldl

SERVER_LIBS_DYNAMIC := -lssl -lcrypto -lpthread -ldl

ifeq ($(DYNAMIC),1)
  SERVER_LIBS := $(SERVER_LIBS_DYNAMIC)
else
  ifneq ($(and $(HAVE_STATIC_SSL),$(HAVE_STATIC_CRYPTO)),)
    SERVER_LIBS := $(SERVER_LIBS_STATIC)
  else
    $(warning static openssl archives not found. linking server dynamically.)
    SERVER_LIBS := $(SERVER_LIBS_DYNAMIC)
  endif
endif

# optional full static attempt
ifeq ($(FULL_STATIC),1)
  SERVER_LIBS := -static -l:libssl.a -l:libcrypto.a -lpthread -ldl
  CLIENT_LIBS := -static -l:libssl.a -l:libcrypto.a -l:libmpg123.a -l:libportaudio.a -lm -lpthread -ldl
endif

.PHONY: all dyn clean info
all: ssl-serveraudio ssl-clientaudio

dyn:
	$(MAKE) DYNAMIC=1 all

ssl-clientaudio: $(CLIENT_SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(CLIENT_LIBS)

ssl-serveraudio: $(SERVER_SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(SERVER_LIBS)

clean:
	rm -f ssl-clientaudio ssl-serveraudio *.o

info:
	@echo "UNAME=$(UNAME)"
	@echo "DYNAMIC=$(DYNAMIC)"
	@echo "HAVE_STATIC_SSL=$(HAVE_STATIC_SSL)"
	@echo "HAVE_STATIC_CRYPTO=$(HAVE_STATIC_CRYPTO)"
	@echo "HAVE_STATIC_MPG123=$(HAVE_STATIC_MPG123)"
	@echo "HAVE_STATIC_PORTAUDIO=$(HAVE_STATIC_PORTAUDIO)"
	@echo "CFLAGS=$(CFLAGS)"
	@echo "LDFLAGS=$(LDFLAGS)"
	@echo "CLIENT_LIBS=$(CLIENT_LIBS)"
	@echo "SERVER_LIBS=$(SERVER_LIBS)"
