# breach_checker

A cross-platform CLI tool that checks whether a password has appeared in known
data breaches, using the HaveIBeenPwned (HIBP) API with **k-anonymity** —
your password never leaves your machine.

---

## How it works

1. Your password is hashed locally with SHA-1
2. Only the **first 5 characters** of the hash are sent to the HIBP API
3. The API returns all hashes that share that prefix (~500 results)
4. The match is checked **locally** — zero exposure risk

---

## Dependencies

| Library   | Purpose          |
|-----------|------------------|
| libcurl   | HTTPS requests   |
| OpenSSL   | SHA-1 hashing    |

### Install dependencies

**Ubuntu / Debian**
```bash
sudo apt install libcurl4-openssl-dev libssl-dev
```

**macOS (Homebrew)**
```bash
brew install curl openssl
```

**Windows (MSYS2 / MinGW)**
```bash
pacman -S mingw-w64-x86_64-curl mingw-w64-x86_64-openssl
```

---

## Build

```bash
git clone https://github.com/XenoCyber0/Breach-Checker.git
cd Breach-Checker
make
```

On macOS if OpenSSL is not found:
```bash
LDFLAGS="-L/opt/homebrew/lib" CFLAGS="-I/opt/homebrew/include" make
```

---

## Usage

```
breach_checker                    Interactive mode (hidden input)
breach_checker <password>         Check a single password
breach_checker -f passwords.txt   Batch check from file
breach_checker -t <password>      Include safety tips
breach_checker -v                 Show version
breach_checker -h                 Show help
```

### Examples

```bash
# Interactive — password hidden while typing
./breach_checker

# Single check
./breach_checker "MyPassword123"

# With tips
./breach_checker -t "hunter2"

# Batch check a list
./breach_checker -f wordlist.txt
```

---

## Output example

```
  SHA-1 prefix sent : 8843D***
  Strength          : Strong
  Querying HIBP API ...
  Status            : COMPROMISED — seen 3,861 times in breach data

  Tips:
  • Change this password on EVERY site you use it
  • Never reuse passwords — use a password manager
  • Enable 2FA on your critical accounts
```

---

## Roadmap

- [ ] Email breach checking (HIBP account API)
- [ ] Export results to CSV / JSON
- [ ] Bulk domain audit mode
- [ ] Config file support (~/.breachrc)
- [ ] Colored output toggle (--no-color)
- [ ] Rate limit handling with retry

---

## License

MIT — free to use, modify, and sell.
