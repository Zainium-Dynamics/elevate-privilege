# Security policy — elevate-pam

elevate-pam is a privileged authentication framework. Treat it like Linux-PAM.

## Hardening defaults

- **TOML-only configuration** — no JSON parsers in the attack surface.
- **Service name sanitization** — path components stripped; `..` rejected.
- **Bounded stacks** — max modules / include depth from `elevate-pam.toml`.
- **Auth token zeroization** — `SecretString` wiped on drop when `secure_mem` is on.
- **Fail-delay** — timing mitigation after failed authentication (configurable).
- **No link-time surprises** — elevate continues to `dlopen` PAM; this library can replace `libpam.so.0` without rebuilding elevate.

## Trusted computing base

- Root-owned config under `/etc/elevate-pam` (mode `0755` dirs, `0644` files recommended).
- Module directory `/lib/security` must not be world-writable.
- Shadow password access requires appropriate privilege; prefer setuid `unix_chkpwd` in locked-down deployments.

## Reporting

Report security issues privately to **alizain@zainiumdynamics.tech**  
(Zainium Dynamics — https://zainiumdynamics.tech).  
Do not file public issues for unfixed privilege-escalation bugs.

## Known limitations (1.0)

- Builtin `chauthtok` is incomplete (returns `PAM_AUTHTOK_ERR`); use carefully for password-change stacks.
- Classic modules that poke private Linux-PAM `pam_handle_t` layout are **not** supported; use the public item/data APIs.
- `unix_chkpwd` helper ships as a packaging stub — production sites should wire the full setuid check path.
