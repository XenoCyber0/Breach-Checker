/*
 * breach_checker.c
 * Cross-platform CLI breach checker using HaveIBeenPwned API (k-anonymity)
 * Supports Windows, Linux, macOS
 *
 * Dependencies:
 *   - libcurl  (HTTP requests)
 *   - OpenSSL  (SHA-1 hashing)
 *
 * Build:
 *   Linux/macOS: gcc breach_checker.c sha1.c -o breach_checker -lcurl -lssl -lcrypto
 *   Windows:     gcc breach_checker.c sha1.c -o breach_checker.exe -lcurl -lssl -lcrypto
 */

#define _POSIX_C_SOURCE 200809L
#include "breach_checker.h"

/* ─── Entry point ─────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    print_banner();

    /* No arguments: interactive mode */
    if (argc == 1) {
        run_interactive();
        return 0;
    }

    /* Parse flags */
    int opt;
    char *file_path  = NULL;
    int   show_tips  = 0;

    while ((opt = parse_args(argc, argv, &file_path, &show_tips)) != -1) {
        switch (opt) {
            case 'h': print_usage(argv[0]); return 0;
            case 'v': printf("breach_checker v%s\n", VERSION);  return 0;
            case 'f': /* file_path already set by parse_args */  break;
            case 't': show_tips = 1;                             break;
            case '?': print_usage(argv[0]);                      return 1;
        }
    }

    /* Single password from command line: breach_checker <password> */
    if (argc > 1 && argv[argc-1][0] != '-') {
        const char *pw = argv[argc-1];
        check_and_print(pw, show_tips);
        return 0;
    }

    /* Batch mode: -f passwords.txt */
    if (file_path) {
        return run_batch(file_path, show_tips);
    }

    print_usage(argv[0]);
    return 1;
}

/* ─── Banner ──────────────────────────────────────────────────────── */

void print_banner(void) {
    printf("\n");
    printf("  ╔══════════════════════════════════════╗\n");
    printf("  ║        BREACH CHECKER v%-6s        ║\n", VERSION);
    printf("  ║  k-anonymity · HIBP API · Cross-plat ║\n");
    printf("  ╚══════════════════════════════════════╝\n");
    printf("\n");
}

void print_usage(const char *prog) {
    printf("Usage:\n");
    printf("  %s                    Interactive mode\n", prog);
    printf("  %s <password>         Check a single password\n", prog);
    printf("  %s -f passwords.txt   Batch check from file\n", prog);
    printf("  %s -t <password>      Show safety tips after check\n", prog);
    printf("  %s -v                 Show version\n", prog);
    printf("  %s -h                 Show this help\n", prog);
    printf("\n");
    printf("Privacy: Only the first 5 chars of the SHA-1 hash are sent.\n");
    printf("Your password never leaves your machine.\n\n");
}

/* ─── Interactive mode ────────────────────────────────────────────── */

void run_interactive(void) {
    char password[MAX_PASSWORD_LEN];

    printf("  Interactive mode — type 'quit' to exit\n");
    printf("  Your password is hashed locally; only 5 chars sent.\n\n");

    while (1) {
        printf("  Password: ");
        fflush(stdout);

        /* Read without echo on supported platforms */
        read_password_hidden(password, sizeof(password));

        if (strcmp(password, "quit") == 0 || strcmp(password, "exit") == 0)
            break;

        if (strlen(password) == 0) {
            printf("  [!] Empty input — try again.\n\n");
            continue;
        }

        check_and_print(password, 1);
        /* Wipe from memory immediately */
        memset(password, 0, sizeof(password));
    }

    printf("\n  Goodbye.\n\n");
}

/* ─── Core check ──────────────────────────────────────────────────── */

void check_and_print(const char *password, int show_tips) {
    char hash[SHA1_HEX_LEN + 1];
    char prefix[HIBP_PREFIX_LEN + 1];
    char suffix[SHA1_HEX_LEN - HIBP_PREFIX_LEN + 1];
    long count = 0;
    int  strength;

    /* 1. Hash */
    sha1_hex(password, hash);
    strncpy(prefix, hash, HIBP_PREFIX_LEN);
    prefix[HIBP_PREFIX_LEN] = '\0';
    strncpy(suffix, hash + HIBP_PREFIX_LEN, sizeof(suffix) - 1);
    suffix[sizeof(suffix) - 1] = '\0';

    /* 2. Strength score */
    strength = password_strength(password);

    printf("\n  SHA-1 prefix sent : %s***\n", prefix);
    printf("  Strength          : %s\n", strength_label(strength));

    /* 3. Query HIBP */
    printf("  Querying HIBP API ...\n");
    int result = query_hibp(prefix, suffix, &count);

    if (result == RESULT_ERROR) {
        printf("  [ERROR] Could not reach the API. Check your connection.\n\n");
        return;
    }

    /* 4. Output */
    if (count == 0) {
        printf("  Status            : " COLOR_GREEN "NOT FOUND" COLOR_RESET
               " — not in any known breach\n");
    } else {
        printf("  Status            : " COLOR_RED "COMPROMISED" COLOR_RESET
               " — seen %ld time%s in breach data\n",
               count, count == 1 ? "" : "s");
    }

    if (show_tips) print_tips(count, strength);
    printf("\n");
}

/* ─── HIBP API query ──────────────────────────────────────────────── */

int query_hibp(const char *prefix, const char *suffix, long *out_count) {
    char url[256];
    ResponseBuffer buf = {0};

    snprintf(url, sizeof(url), "%s%s", HIBP_API_URL, prefix);

    buf.data = malloc(1);
    buf.size = 0;

    CURL *curl = curl_easy_init();
    if (!curl) {
        free(buf.data);      // ← free before exit
        return RESULT_ERROR;
    }

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Add-Padding: true");

    curl_easy_setopt(curl, CURLOPT_URL,            url);
    curl_easy_setopt(curl, CURLOPT_USERAGENT,      "breach_checker/" VERSION);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER,     headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,  write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,      &buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,        10L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        free(buf.data);
        return RESULT_ERROR;
    }

    /* Parse response: each line is "HASH_SUFFIX:COUNT" */
    *out_count = 0;
    char *line = strtok(buf.data, "\n");
    while (line) {
        /* Strip \r if present */
        char *cr = strchr(line, '\r');
        if (cr) *cr = '\0';

        char *colon = strchr(line, ':');
        if (colon) {
            *colon = '\0';
            /* Case-insensitive compare */
            if (strcasecmp(line, suffix) == 0) {
                *out_count = atol(colon + 1);
                break;
            }
        }
        line = strtok(NULL, "\n");
    }

    free(buf.data);
    return RESULT_OK;
}

/* ─── libcurl write callback ──────────────────────────────────────── */

size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t total = size * nmemb;
    ResponseBuffer *buf = (ResponseBuffer *)userp;

    char *ptr = realloc(buf->data, buf->size + total + 1);
    if (!ptr) return 0;

    buf->data = ptr;
    memcpy(buf->data + buf->size, contents, total);
    buf->size += total;
    buf->data[buf->size] = '\0';
    return total;
}

/* ─── Batch mode ──────────────────────────────────────────────────── */

int run_batch(const char *filepath, int show_tips) {
    FILE *f = fopen(filepath, "r");
    if (!f) {
        fprintf(stderr, "  [ERROR] Cannot open file: %s\n", filepath);
        return 1;
    }

    char line[MAX_PASSWORD_LEN];
    int total = 0, safe = 0, breached = 0;

    printf("  Batch mode — reading from: %s\n\n", filepath);

    while (fgets(line, sizeof(line), f)) {
        /* Strip newline */
        line[strcspn(line, "\r\n")] = '\0';
        if (strlen(line) == 0) continue;

        total++;
        printf("  [%d] Checking: %s\n", total, line);
        check_and_print(line, show_tips);

        /* Small delay to respect API rate limits */
        platform_sleep_ms(200);
    }

    fclose(f);

    printf("  ─────────────────────────────\n");
    printf("  Batch summary\n");
    printf("  Total checked : %d\n", total);
    printf("  Safe          : " COLOR_GREEN "%d" COLOR_RESET "\n", safe);
    printf("  Breached      : " COLOR_RED "%d" COLOR_RESET "\n", breached);
    printf("\n");
    return 0;
}

/* ─── Password strength ───────────────────────────────────────────── */

int password_strength(const char *pw) {
    int score = 0;
    int len   = (int)strlen(pw);

    if (len >= 8)  score++;
    if (len >= 14) score++;
    if (len >= 20) score++;

    int has_upper = 0, has_lower = 0, has_digit = 0, has_symbol = 0;
    for (int i = 0; i < len; i++) {
        if (isupper((unsigned char)pw[i])) has_upper  = 1;
        if (islower((unsigned char)pw[i])) has_lower  = 1;
        if (isdigit((unsigned char)pw[i])) has_digit  = 1;
        if (ispunct((unsigned char)pw[i])) has_symbol = 1;
    }
    score += has_upper + has_lower + has_digit + has_symbol;
    if (score > 5) score = 5;
    return score;
}

const char *strength_label(int score) {
    switch (score) {
        case 0: case 1: return COLOR_RED    "Very Weak"  COLOR_RESET;
        case 2:         return COLOR_RED    "Weak"       COLOR_RESET;
        case 3:         return COLOR_YELLOW "Fair"       COLOR_RESET;
        case 4:         return COLOR_GREEN  "Strong"     COLOR_RESET;
        default:        return COLOR_GREEN  "Very Strong" COLOR_RESET;
    }
}

/* ─── Tips ────────────────────────────────────────────────────────── */

void print_tips(long count, int strength) {
    printf("\n  Tips:\n");
    if (count > 0) {
        printf("  • Change this password on EVERY site you use it\n");
        printf("  • Never reuse passwords — use a password manager\n");
        printf("  • Enable 2FA on your critical accounts\n");
    } else {
        printf("  • Great! Keep using unique passwords per site\n");
        if (strength < 4)
            printf("  • Consider making it longer with symbols for extra strength\n");
        printf("  • Re-check periodically — new breaches happen daily\n");
    }
}

/* ─── Hidden password input ───────────────────────────────────────── */

void read_password_hidden(char *buf, size_t len) {
#ifdef _WIN32
    size_t i = 0;
    while (i < len - 1) {
        int c = _getch();
        if (c == '\r' || c == '\n') break;
        if (c == '\b' && i > 0) { i--; continue; }
        buf[i++] = (char)c;
    }
    buf[i] = '\0';
    printf("\n");
#else
    struct termios old, new_t;
    tcgetattr(STDIN_FILENO, &old);
    new_t = old;
    new_t.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &new_t);
    if (fgets(buf, (int)len, stdin))
        buf[strcspn(buf, "\n")] = '\0';
    tcsetattr(STDIN_FILENO, TCSANOW, &old);
    printf("\n");
#endif
}

/* ─── Cross-platform sleep ────────────────────────────────────────── */

void platform_sleep_ms(int ms) {
#ifdef _WIN32
    Sleep(ms);
#else
    usleep(ms * 1000);
#endif
}

/* ─── Argument parsing ────────────────────────────────────────────── */

int parse_args(int argc, char *argv[], char **file_path, int *show_tips) {
    static int idx = 1;
    if (idx >= argc) return -1;

    const char *arg = argv[idx++];
    if (arg[0] != '-') { idx--; return -1; }

    switch (arg[1]) {
        case 'h': return 'h';
        case 'v': return 'v';
        case 't': return 't';
        case 'f':
            if (idx < argc) { *file_path = argv[idx++]; return 'f'; }
            return '?';
        default: return '?';
    }
}
