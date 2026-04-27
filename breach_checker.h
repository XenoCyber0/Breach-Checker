/*
 * breach_checker.h
 * Cross-platform password breach checker
 */

#ifndef BREACH_CHECKER_H
#define BREACH_CHECKER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef _WIN32
  #include <windows.h>
  #include <conio.h>
#else
  #include <termios.h>
  #include <unistd.h>
  #include <strings.h>  /* strcasecmp */
#endif

#include <curl/curl.h>
#include <openssl/sha.h>

/* ─── Version ─────────────────────────────────────────────────────── */
#define VERSION          "1.0.0"

/* ─── HIBP API ────────────────────────────────────────────────────── */
#define HIBP_API_URL     "https://api.pwnedpasswords.com/range/"
#define HIBP_PREFIX_LEN  5

/* ─── Limits ──────────────────────────────────────────────────────── */
#define MAX_PASSWORD_LEN 1024
#define SHA1_HEX_LEN     40

/* ─── Result codes ────────────────────────────────────────────────── */
#define RESULT_OK        0
#define RESULT_ERROR    -1

/* ─── ANSI colors (disabled on Windows by default) ───────────────── */
#ifdef _WIN32
  #define COLOR_RED    ""
  #define COLOR_GREEN  ""
  #define COLOR_YELLOW ""
  #define COLOR_RESET  ""
#else
  #define COLOR_RED    "\033[31m"
  #define COLOR_GREEN  "\033[32m"
  #define COLOR_YELLOW "\033[33m"
  #define COLOR_RESET  "\033[0m"
#endif

/* ─── Response buffer for libcurl ─────────────────────────────────── */
typedef struct {
    char  *data;
    size_t size;
} ResponseBuffer;

/* ─── SHA-1 helper (implemented in sha1.c) ───────────────────────── */
void sha1_hex(const char *input, char out_hex[SHA1_HEX_LEN + 1]);

/* ─── Function prototypes ─────────────────────────────────────────── */
void        print_banner(void);
void        print_usage(const char *prog);
void        run_interactive(void);
void        check_and_print(const char *password, int show_tips);
int         query_hibp(const char *prefix, const char *suffix, long *out_count);
size_t      write_callback(void *contents, size_t size, size_t nmemb, void *userp);
int         run_batch(const char *filepath, int show_tips);
int         password_strength(const char *pw);
const char *strength_label(int score);
void        print_tips(long count, int strength);
void        read_password_hidden(char *buf, size_t len);
void        platform_sleep_ms(int ms);
int         parse_args(int argc, char *argv[], char **file_path, int *show_tips);

#endif /* BREACH_CHECKER_H */
