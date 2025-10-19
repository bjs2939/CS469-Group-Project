# Makefile (clean, server static by default)

CC      := gcc
UNAME   := $(shell uname)

CLIENT_SRC := ssl-clientaudio.c
SERVER_SRC := ssl-serveraudio.c

# Build knobs
# DYNAMIC=1 -> force fully dynamic on both targets (use: `make dyn`)
DYNAMIC ?= 0

# Paths (adjust if needed)
OPENSSL_LIBDIR ?= /usr/lib/x86_64-linux-gnu
AUDIO_LIBDIR   ?= /usr/lib/x86_64-linux-gnu

# Flags
CFLAGS   ?= -O2 -Wall -pthread
LDFLAGS  ?=
CFLAGS   += -I$(OPENSSL_LIBDIR)/include
LDFLAGS  += -L$(OPENSSL_LIBDIR) -L$(AUDIO_LIBDIR)

ifeq ($(UNAME),Darwin)
  CFLAGS  += -I/usr/local/opt/openssl/include
  LDFLAGS += -L/usr/local/opt/openssl/lib
endif

# Detect static archives
HAVE_STATIC_SSL       := $(wildcard $(OPENSSL_LIBDIR)/libssl.a)
HAVE_STATIC_CRYPTO    := $(wildcard $(OPENSSL_LIBDIR)/libcrypto.a)
HAVE_STATIC_MPG123    := $(wildcard $(AUDIO_LIBDIR)/libmpg123.a)
HAVE_STATIC_PORTAUDIO := $(wildcard $(AUDIO_LIBDIR)/libportaudio.a)

# ------------------------------
# Library sets

# Use -pthread, and add -ldl -lz since static OpenSSL often needs them
CLIENT_LIBS_STATIC := \
  -Wl,-Bstatic -l:libssl.a -l:libcrypto.a -l:libmpg123.a -l:libportaudio.a \
  -Wl,-Bdynamic -lm -pthread -ldl -lz

CLIENT_LIBS_DYNAMIC := -lssl -lcrypto -lmpg123 -lportaudio -lm -pthread -ldl -lz

SERVER_LIBS_STATIC := \
  -Wl,-Bstatic -l:libssl.a -l:libcrypto.a \
  -Wl,-Bdynamic -pthread -ldl -lz

SERVER_LIBS_DYNAMIC := -lssl -lcrypto -pthread -ldl -lz

# ------------------------------
# Choose client libs
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
# Choose server libs
# Requirement: server builds statically by default
ifeq ($(DYNAMIC),1)
  SERVER_LIBS := $(SERVER_LIBS_DYNAMIC)
else
  ifneq ($(and $(HAVE_STATIC_SSL),$(HAVE_STATIC_CRYPTO)),)
    SERVER_LIBS := $(SERVER_LIBS_STATIC)
  else
    $(error static OpenSSL archives not found in $(OPENSSL_LIBDIR). Use `make dyn` to build dynamically or install static libssl/libcrypto)
  endif
endif

# Optional full static attempt (not recommended; often fails on glibc)
ifeq ($(FULL_STATIC),1)
  SERVER_LIBS := -static -l:libssl.a -l:libcrypto.a -pthread -ldl -lz
  CLIENT_LIBS := -static -l:libssl.a -l:libcrypto.a -l:libmpg123.a -l:libportaudio.a -lm -pthread -ldl -lz
endif

# ------------------------------
.PHONY: all dyn clean info
all: ssl-serveraudio ssl-clientaudio

dyn:
	$(MAKE) DYNAMIC=1 all

ssl-serveraudio: $(SERVER_SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(SERVER_LIBS)

ssl-clientaudio: $(CLIENT_SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(CLIENT_LIBS)

clean:
	rm -f ssl-serveraudio ssl-clientaudio *.o

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