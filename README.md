# mailauth-lint

**Catch the e-mail authentication record mistakes that silently break your mail.** SPF, DMARC and DKIM live in DNS TXT records, and the
errors are quiet: an SPF record with 11 `include`s fails with a permerror, two SPF records cancel each other, `p=none` never blocks
anything, a 1024-bit DKIM key is below current advice. mailauth-lint reads record **text** you paste or keep in a file and lists what
is wrong. It makes **no DNS lookups** (so it needs no network and nothing leaves your machine) and executes nothing it reads.

```
$ mailauth-lint dns.txt
example.com. [SPF] line 1
  ERROR   spf-plus-all             +all (or bare 'all') authorizes every sender on the internet and defeats SPF
  WARNING spf-ptr                  ptr is deprecated (RFC 7208 section 5.5): slow, unreliable and discouraged; replace it with ip4/ip6/include
  WARNING spf-redirect-with-all    redirect= is ignored when the record also has an 'all' mechanism (RFC 7208 section 6.1); remove one of them
  INFO    spf-lookup-count         5 lookup-causing mechanism(s) here; lookups inside included records cannot be counted offline
  INFO    spf-void-unchecked       void lookups (names that do not exist or return nothing, limit 2) cannot be checked offline
_dmarc.example.com. [DMARC] line 2
  ERROR   dmarc-uri                ruf has an invalid mailto address: mailto:bad
  WARNING dmarc-p-none             p=none only monitors and blocks nothing; move to quarantine then reject once reports look clean
  WARNING dmarc-pct                pct=50 applies the policy to only part of the mail; use 100 when you are done rolling out
  WARNING dmarc-no-rua             no rua= address: you will receive no aggregate reports, so you cannot see who sends as your domain
  INFO    dmarc-sp-inherits        no sp= tag: subdomains inherit p=none
  INFO    dmarc-ruf                ruf (failure reports) is honoured by few receivers and may carry message content; rua is the useful one
  INFO    dmarc-alignment-default  adkim and aspf are unset: both default to relaxed alignment
sel1._domainkey.example.com. [DKIM] line 3
  WARNING dkim-testing             t=y marks the domain as testing: verifiers may treat failures as no signature; remove it in production
  WARNING dkim-short-key           RSA key is 1024 bits; 2048 bits or more is recommended (RFC 8301 requires 1024 minimum)
note: offline only: no DNS lookups were made, so includes, redirects, void lookups and report authorizations are not verified
3 record(s): 2 error(s), 7 warning(s), 5 info
$ mailauth-lint --type spf -r "v=spf1 ip4:192.0.2.0/24 -all"
(input) [SPF] line 1
  OK     no findings
note: offline only: no DNS lookups were made, so includes, redirects, void lookups and report authorizations are not verified
1 record(s): 0 error(s), 0 warning(s), 0 info
```

One file, standard library only (the DKIM key size comes from a small hand-written DER parser).

## Usage

```
mailauth-lint [files ...] [-r RECORD] [--type auto|spf|dmarc|dkim] [--fail-on info|warning|error|never] [--json]
```

- Input lines: `example.com. 3600 IN TXT "v=spf1 ..."` (TTL and `IN` optional, several quoted strings are joined the way DNS does) or a bare
  record string such as `v=DMARC1; p=none`. Use `--type` when a bare string does not start with `v=spf1`, `v=DMARC1` or `v=DKIM1`.
  `-` reads stdin; with no arguments stdin is read. `-r` gives a record inline and can be repeated. Lines starting with `#` or `;` are comments.
- Severity: `error` (broken or unsafe), `warning` (weak or risky), `info` (guidance). `--fail-on` (default `warning`) sets the lowest
  severity that makes the exit code 1.
- `--json` prints `{"records": [...], "summary": {...}, "notes": [...]}`.

Exit codes: `0` nothing at or above `--fail-on`, `1` findings at or above `--fail-on`, `2` usage or input error (unreadable file, binary input, no records).

## What it checks

| Record | Checks |
|---|---|
| SPF | more than 10 lookup-causing mechanisms (`include`, `a`, `mx`, `ptr`, `exists`, `redirect`); `+all`, bare `all`, `?all`, `~all` guidance; deprecated `ptr`; several SPF records at one name; syntax (unknown terms, bad IPs, bad CIDR, `include=`); `redirect` together with `all`; terms after `all`; duplicate `include`; strings over 255 characters and records over about 450 |
| DMARC | `p=none`; missing `rua`; `pct` below 100; `sp`; `adkim`/`aspf` values; unknown, duplicate or invalid tags; `rua`/`ruf` mailto URI syntax and `!size`; record not at `_dmarc.`; several DMARC records |
| DKIM | missing `p=`; empty `p=` (revoked); `t=y` testing; `k=` type; RSA key size decoded from the base64 DER public key (under 2048 bits warns, under 1024 is an error); ed25519 length; `h=sha1`; bad base64 |

## Limits

- **No DNS.** It cannot expand `include`/`redirect` chains, so lookups inside included records are not counted (your real count can be higher
  than the one it shows). **Void lookups** (names that do not exist, limit 2) cannot be checked; it says so on every SPF record that has lookups.
  It also cannot confirm that a DMARC report address in another domain has published the authorization record, or that a DKIM selector exists.
- Bare records without a name are treated as one group, so two bare SPF lines produce only a warning (they may belong to different domains).
- Macros (`%{i}`) in SPF domains are accepted without being expanded.
- Key size comes from the DER structure only; the key itself is not validated as a real RSA key.
- Guidance follows RFC 7208, RFC 7489 and RFC 6376/8301 as understood by the author; receivers differ in how strictly they behave, so treat warnings as advice.
- Input is capped at 1 MiB and 5000 records.

---

**More tools by [TPOALOS](https://github.com/TPOALOS):** [dmarc-report](https://github.com/TPOALOS/dmarc-report) · [nginxcheck](https://github.com/TPOALOS/nginxcheck) · [cookiecheck](https://github.com/TPOALOS/cookiecheck) · [all 51 tools](https://tpoalos.github.io)
