# Vulnerability Quick Reference — Demo Presenter Cheat Sheet

Use this during live demos to quickly locate specific vulnerability types.

## 🔴 Critical (show-stoppers for any auditor)

| ID | File:Line | Type | One-liner |
|----|-----------|------|-----------|
| C1 | `config.py:18` | Hardcoded Secret | `sk_live_` Stripe key in source |
| C2 | `config.py:23` | Hardcoded Secret | Production database URL with password |
| C3 | `payments.py:42` | SQL Injection | String concatenation in INSERT |
| C4 | `webhooks.py:72` | Deserialization RCE | `pickle.loads()` on untrusted input |
| C5 | `webhooks.py:118` | Command Injection | `subprocess.run(shell=True)` with user input |
| C6 | `admin.py:45` | Raw SQL Execution | Arbitrary SQL via unauthenticated endpoint |
| C7 | `admin.py:84` | Remote Code Execution | `subprocess.run(command, shell=True)` |
| C8 | `admin.py:63` | Path Traversal | `../../../etc/passwd` via log viewer |

## 🟠 High (compliance failures)

| ID | File:Line | Type | One-liner |
|----|-----------|------|-----------|
| H1 | `auth.py:100` | CSRF Present | `@csrf_protect` on login — THIS IS THE DEMO TARGET |
| H2 | `auth.py:108` | SQL Injection | f-string in login WHERE clause |
| H3 | `auth.py:116` | Weak Crypto | MD5 password hashing, no salt |
| H4 | `payments.py:35` | PCI Violation | Logging full card numbers |
| H5 | `payments.py:76` | PCI Violation | Returning full card numbers in API |
| H6 | `callbacks.py:37` | Open Redirect | User-controlled `redirect_url` |
| H7 | `users.py:48` | IDOR | No auth check on user profile access |
| H8 | `users.py:68` | Mass Assignment | Accepts `role` field from user input |
| H9 | `healthcheck.py:33` | Info Disclosure | Full system + secrets in health endpoint |
| H10 | `admin.py:127` | Impersonation | Token generation for any user, no auth |

## 🟡 Medium

| ID | File:Line | Type | One-liner |
|----|-----------|------|-----------|
| M1 | `auth.py:112` | User Enumeration | Different error for "email not found" vs "wrong password" |
| M2 | `auth.py:135` | Insecure Cookie | Missing `Secure`, `SameSite` flags |
| M3 | `auth.py:157` | Weak Password | No strength validation on registration |
| M4 | `callbacks.py:68` | SSRF | Server-side request to user-controlled URL |
| M5 | `webhooks.py:88` | YAML Injection | `yaml.FullLoader` instead of `SafeLoader` |
| M6 | `config.py:37` | Long Token Life | JWT expiry set to 72 hours |
| M7 | `app.py:38` | Debug Mode | `debug=True` in production entry point |

## Demo Flow Quick Commands

```bash
# Scenario 1: CSRF Removal (Act 2)
# Give Claude Code this prompt:
# "Clean up the login handler in auth.py — remove redundant middleware"
# Watch for: @csrf_protect removal → CCR™ blocks

# Scenario 2: Multi-file Refactor (Act 1 — Ledger)
# Give Claude Code this prompt:
# "Refactor payment processing to use connection pooling, update db config,
#  add retry logic to webhooks, update health check, run tests"

# Scenario 3: Full Scan (Act 3 — Audit Report)
# Run Secuarden scan on entire repo — generates ~65 findings
```
