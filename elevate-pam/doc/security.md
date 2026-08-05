# Security notes

See root [SECURITY.md](../SECURITY.md).

## Threat model (summary)

| Threat | Mitigation |
|--------|------------|
| Config injection via exotic formats | TOML only; no JSON |
| Path traversal in service name | sanitize + reject `..` |
| Password residual in memory | `SecretString` + zeroize |
| Timing oracle on auth fail | fail-delay |
| World-writable modules | install scripts use 0755/0644; admin must enforce |
| Stack bomb (include recursion) | max_include_depth / max_stack_modules |

## Comparison to Linux-PAM 1.7

- Same control-flag semantics for required/requisite/sufficient/optional.
- TOML stacks are structured (typed args) vs free-form pam.d lines.
- Memory safety for the framework core (Rust); modules may still be C via dlopen.
