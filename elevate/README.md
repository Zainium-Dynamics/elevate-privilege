# `elevate` — Privilege Escalation Engine ⚡

[![License](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](../LICENSE-APACHE)

**`elevate`** is the core privilege escalation crate within the `elevate-privilege` workspace. It provides memory-safe binaries for executing commands with elevated permissions while preserving user environment configuration and auditing actions.

> [!NOTE]
> **Lineage & Customization**: The `elevate` binary core was originally forked from `sudo-rs`. It has been heavily refactored, extended, and integrated into the unified workspace with custom rate limiters, security policies, and native `elevate-pam` / `elevate-crypto` bindings.

---

## 🎯 Included Binaries

### 1. `elevate`
Main privilege escalation executable. Replaces legacy `sudo`.
- **Environment Preservation**: Safely forwards user shell environment variables.
- **PAM Integration**: Uses `elevate-pam` for authentication and session validation.
- **Syslog Audit**: Logs all invocations to `LOG_AUTHPRIV`.

### 2. `elev`
Lightweight privilege escalation tool. Replaces legacy `doas`.
- Fast execution path for simple commands without heavy environment loading.

### 3. `vielev`
Interactive editor wrapper for privilege configuration files. Replaces `visudo`.
- Uses atomic file lock protection to prevent concurrent edit corruption.
- Verifies configuration syntax before saving.

---

## 🚀 Usage Examples

```bash
# Run command as root
elevate systemctl restart nginx

# Run command as specific user
elevate -u postgres psql

# Edit elevate configuration safely
vielev
```

---

## 📄 License

Distributed under your choice of the **MIT license** or the **Apache License 2.0**. See [`../LICENSE-MIT`](../LICENSE-MIT) and [`../LICENSE-APACHE`](../LICENSE-APACHE) for details.
