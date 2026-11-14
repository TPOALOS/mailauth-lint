# Changelog

## 1.0.0

First release.

- Lints SPF (lookup count, +all/?all/~all, ptr, multiple records, syntax, redirect with all, string and record length), DMARC (p=none, rua, pct, sp, alignment, tag values, rua/ruf URIs) and DKIM key records (revoked, testing flag, key type, RSA key size decoded from the DER public key)
- Reads `name TXT "..."` lines or bare strings with `--type`; text and `--json` output; `--fail-on` controls the exit code
- Offline only: makes no DNS lookups and says which checks that rules out
