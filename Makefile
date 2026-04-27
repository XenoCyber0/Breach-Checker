# Makefile — breach_checker
# Supports Linux, macOS, Windows (MinGW)

CC      = gcc
TARGET  = breach_checker
SRCS    = breach_checker.c sha1.c
CFLAGS  = -Wall -Wextra -O2 -std=c11
LIBS    = -lcurl -lssl -lcrypto

# ── Platform detection ─────────────────────────────────────────────────
UNAME := $(shell uname -s 2>/dev/null || echo Windows)

ifeq ($(UNAME), Windows)
    TARGET  := breach_checker.exe
    LIBS    += -lws2_32
endif

ifeq ($(UNAME), Darwin)
    # Homebrew paths on macOS
    CFLAGS  += -I/opt/homebrew/include
    LDFLAGS += -L/opt/homebrew/lib
endif

# ── Targets ────────────────────────────────────────────────────────────
all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS) $(LIBS)

clean:
	rm -f $(TARGET) *.o

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

.PHONY: all clean install
