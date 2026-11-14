#!/usr/bin/env python3
"""mailauth-lint: offline linter for SPF, DMARC and DKIM DNS record text.

Reads record text you paste or keep in a file. It never performs DNS lookups,
never opens a network connection and never executes anything it reads.

Exit codes: 0 nothing at or above --fail-on, 1 findings at or above --fail-on,
2 usage or input error.
"""

import argparse
import base64
import binascii
import ipaddress
import json
import re
import sys

__version__ = "1.0.0"

MAX_INPUT_BYTES = 1024 * 1024
MAX_RECORDS = 5000
SEV_RANK = {"info": 0, "warning": 1, "error": 2}
DEFAULT_NAME = "(input)"

LINE_RE = re.compile(
    r"^(?P<name>\S+)\s+(?:(?P<ttl>\d+)\s+)?(?:(?:IN|CH)\s+)?(?P<rtype>TXT|SPF)\s+(?P<rest>.*)$",
    re.IGNORECASE,
)
QUOTED_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}\.?$)([A-Za-z0-9_]([A-Za-z0-9_\-]{0,61}[A-Za-z0-9_])?\.)*"
    r"[A-Za-z0-9_]([A-Za-z0-9_\-]{0,61}[A-Za-z0-9_])?\.?$"
)
MAILTO_RE = re.compile(
    r"^[^@\s,;!<>\"]+@[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?"
    r"(\.[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?)+$"
)
SPF_MECH_RE = re.compile(
    r"^(?P<q>[+\-~?])?(?P<m>all|include|a|mx|ptr|ip4|ip6|exists)(?P<arg>[:/].*)?$",
    re.IGNORECASE,
)
SPF_MOD_RE = re.compile(r"^(?P<n>[A-Za-z][A-Za-z0-9_.\-]*)=(?P<v>.*)$")
DUAL_CIDR_RE = re.compile(r"^(?:/(\d{1,2}))?(?://(\d{1,3}))?$")


def safe(text, limit=200):
    """Make arbitrary text printable: escape control and format characters."""
    out = []
    for ch in str(text):
        if ch == "\\":
            out.append("\\\\")
        elif ch.isprintable():
            out.append(ch)
        elif ord(ch) < 0x100:
            out.append("\\x%02x" % ord(ch))
        elif ord(ch) < 0x10000:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append("\\U%08x" % ord(ch))
    s = "".join(out)
    if len(s) > limit:
        s = s[:limit] + "..."
    return s


# --------------------------------------------------------------------------
# input parsing
# --------------------------------------------------------------------------

def _unescape(s):
    s = re.sub(r"\\(\d{3})", lambda m: chr(int(m.group(1))) if int(m.group(1)) < 256 else "?", s)
    return re.sub(r"\\(.)", r"\1", s)


def parse_input(text, forced_type="auto"):
    """Return list of record dicts parsed from the text."""
    records = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        name = DEFAULT_NAME
        rtype = "TXT"
        rest = line
        m = LINE_RE.match(line)
        if m:
            name = m.group("name")
            rtype = m.group("rtype").upper()
            rest = m.group("rest").strip()
        rest = rest.strip()
        quoted = False
        if rest.startswith('"'):
            strings = [_unescape(s) for s in QUOTED_RE.findall(rest)]
            quoted = True
        else:
            strings = [rest]
        records.append({
            "name": name,
            "rtype": rtype,
            "line": lineno,
            "strings": strings,
            "quoted": quoted,
            "text": "".join(strings),
        })
        if len(records) >= MAX_RECORDS:
            break
    for rec in records:
        rec["kind"] = classify(rec["text"], forced_type)
    return records


def classify(text, forced_type):
    if forced_type != "auto":
        return forced_type
    t = text.strip().lower()
    if re.match(r"^v\s*=\s*spf1(\s|$)", t):
        return "spf"
    if re.match(r"^v\s*=\s*dmarc1\s*(;|$)", t) or t.startswith("v=dmarc"):
        return "dmarc"
    if re.match(r"^v\s*=\s*dkim1\s*(;|$)", t) or t.startswith("v=dkim"):
        return "dkim"
    return None


# --------------------------------------------------------------------------
# generic helpers
# --------------------------------------------------------------------------

def parse_tags(text):
    """Split 'a=b; c=d' into ordered (tag, value) pairs plus syntax problems."""
    pairs = []
    problems = []
    for piece in text.split(";"):
        piece = piece.strip()
        if not piece:
            continue
        if "=" not in piece:
            problems.append(piece)
            continue
        k, v = piece.split("=", 1)
        pairs.append((k.strip().lower(), v.strip()))
    return pairs, problems


def check_string_lengths(rec, add, total_limit=None):
    for i, s in enumerate(rec["strings"], 1):
        if len(s) > 255:
            if rec["quoted"]:
                add("error", "string-too-long",
                    "character-string %d is %d bytes; a single TXT string is limited to 255, "
                    "split it into several quoted strings" % (i, len(s)))
            else:
                add("warning", "string-too-long",
                    "record is %d characters as one unquoted string; a single TXT string is limited "
                    "to 255, make sure it is split into several quoted strings in DNS" % len(s))
    if total_limit and len(rec["text"]) > total_limit:
        add("warning", "record-long",
            "record is %d characters; keep it under about %d so the whole DNS answer fits in one "
            "UDP packet" % (len(rec["text"]), total_limit))


# --------------------------------------------------------------------------
# SPF
# --------------------------------------------------------------------------

def _domain_ok(dom):
    if not dom:
        return False
    if "%" in dom:
        return True
    return bool(DOMAIN_RE.match(dom))


def lint_spf(rec, add):
    text = rec["text"].strip()
    if rec["rtype"] == "SPF":
        add("warning", "spf-rr-type", "record uses the obsolete SPF RR type; publish it as TXT (RFC 7208)")
    check_string_lengths(rec, add, total_limit=450)
    terms = text.split()
    if not terms or terms[0].lower() != "v=spf1":
        add("error", "spf-version", "record must start with v=spf1")
        terms = terms[1:] if terms else []
    else:
        terms = terms[1:]
    lookups = 0
    lookup_items = []
    seen_all = None
    after_all = []
    redirects = 0
    has_redirect = False
    exp_count = 0
    seen_includes = set()
    for term in terms:
        if seen_all is not None:
            after_all.append(term)
        m = SPF_MECH_RE.match(term)
        if m:
            q = m.group("q") or "+"
            mech = m.group("m").lower()
            arg = m.group("arg") or ""
            if mech == "all":
                if arg:
                    add("error", "spf-syntax", "'all' takes no argument: %s" % safe(term))
                if seen_all is None:
                    seen_all = q
            elif mech in ("include", "exists"):
                if not arg.startswith(":") or not _domain_ok(arg[1:]):
                    add("error", "spf-syntax", "%s needs a valid domain (%s:domain): %s" % (mech, mech, safe(term)))
                else:
                    lookups += 1
                    lookup_items.append(mech)
                    if mech == "include":
                        d = arg[1:].lower().rstrip(".")
                        if d in seen_includes:
                            add("warning", "spf-duplicate-include", "include:%s appears more than once and wastes lookups" % safe(d))
                        seen_includes.add(d)
            elif mech in ("a", "mx"):
                lookups += 1
                lookup_items.append(mech)
                _check_dual_cidr(mech, arg, term, add)
            elif mech == "ptr":
                lookups += 1
                lookup_items.append("ptr")
                add("warning", "spf-ptr", "ptr is deprecated (RFC 7208 section 5.5): slow, unreliable and discouraged; replace it with ip4/ip6/include")
                if arg and (not arg.startswith(":") or not _domain_ok(arg[1:])):
                    add("error", "spf-syntax", "ptr domain is invalid: %s" % safe(term))
            elif mech in ("ip4", "ip6"):
                _check_ip(mech, arg, term, add)
            continue
        m = SPF_MOD_RE.match(term)
        if m:
            name = m.group("n").lower()
            val = m.group("v")
            if name in ("include", "a", "mx", "ptr", "ip4", "ip6", "exists", "all"):
                add("error", "spf-syntax", "'%s' is a mechanism and uses ':' not '=': %s" % (name, safe(term)))
            elif name == "redirect":
                redirects += 1
                has_redirect = True
                if not _domain_ok(val):
                    add("error", "spf-syntax", "redirect needs a valid domain: %s" % safe(term))
                else:
                    lookups += 1
                    lookup_items.append("redirect")
            elif name == "exp":
                exp_count += 1
                if not _domain_ok(val):
                    add("error", "spf-syntax", "exp needs a valid domain: %s" % safe(term))
            else:
                add("info", "spf-unknown-modifier", "unknown modifier '%s' is ignored by receivers" % safe(name))
            continue
        add("error", "spf-syntax", "unrecognized term: %s" % safe(term))
    if redirects > 1:
        add("error", "spf-multiple-redirect", "redirect modifier appears %d times; only one is allowed" % redirects)
    if exp_count > 1:
        add("error", "spf-multiple-exp", "exp modifier appears %d times; only one is allowed" % exp_count)
    if after_all:
        add("warning", "spf-after-all", "terms after 'all' are never evaluated: %s" % safe(" ".join(after_all)))
    if has_redirect and seen_all is not None:
        add("warning", "spf-redirect-with-all",
            "redirect= is ignored when the record also has an 'all' mechanism (RFC 7208 section 6.1); remove one of them")
    if seen_all is None and not has_redirect:
        add("warning", "spf-no-all", "no 'all' mechanism or redirect: unmatched senders get a neutral result; end the record with -all (or ~all while rolling out)")
    if seen_all == "+":
        add("error", "spf-plus-all", "+all (or bare 'all') authorizes every sender on the internet and defeats SPF")
    elif seen_all == "?":
        add("warning", "spf-neutral-all", "?all states no policy; use ~all while testing and -all when the sender list is complete")
    elif seen_all == "~":
        add("info", "spf-softfail-all", "~all is fine while rolling out; with DMARC enforced, -all is the stricter end state")
    if lookups > 10:
        add("error", "spf-lookup-limit",
            "%d DNS-lookup mechanisms in this record (%s); more than 10 causes a permerror (RFC 7208 section 4.6.4)"
            % (lookups, ", ".join(lookup_items)))
    elif lookups == 10:
        add("warning", "spf-lookup-limit",
            "exactly 10 DNS-lookup mechanisms in this record; nested includes count too, so you are likely over the limit")
    if lookups:
        add("info", "spf-lookup-count",
            "%d lookup-causing mechanism(s) here; lookups inside included records cannot be counted offline" % lookups)
        add("info", "spf-void-unchecked",
            "void lookups (names that do not exist or return nothing, limit 2) cannot be checked offline")


def _check_dual_cidr(mech, arg, term, add):
    if not arg:
        return
    rest = arg
    if arg.startswith(":"):
        dom = arg[1:].split("/", 1)[0]
        if not _domain_ok(dom):
            add("error", "spf-syntax", "%s domain is invalid: %s" % (mech, safe(term)))
            return
        rest = arg[1 + len(dom):]
    m = DUAL_CIDR_RE.match(rest)
    if not m:
        add("error", "spf-syntax", "%s has a bad CIDR suffix: %s" % (mech, safe(term)))
        return
    if m.group(1) and int(m.group(1)) > 32:
        add("error", "spf-syntax", "%s IPv4 prefix length above 32: %s" % (mech, safe(term)))
    if m.group(2) and int(m.group(2)) > 128:
        add("error", "spf-syntax", "%s IPv6 prefix length above 128: %s" % (mech, safe(term)))


def _check_ip(mech, arg, term, add):
    if not arg.startswith(":") or len(arg) < 2:
        add("error", "spf-syntax", "%s needs an address (%s:address): %s" % (mech, mech, safe(term)))
        return
    try:
        if mech == "ip4":
            net = ipaddress.IPv4Network(arg[1:], strict=False)
            if net.prefixlen < 16:
                add("warning", "spf-broad-ip", "%s authorizes %d addresses; that is very broad" % (safe(term), net.num_addresses))
        else:
            net = ipaddress.IPv6Network(arg[1:], strict=False)
            if net.prefixlen < 32:
                add("warning", "spf-broad-ip", "%s is a very broad IPv6 range" % safe(term))
    except ValueError:
        add("error", "spf-syntax", "invalid %s address or prefix: %s" % (mech, safe(term)))


# --------------------------------------------------------------------------
# DMARC
# --------------------------------------------------------------------------

DMARC_KNOWN = {"v", "p", "sp", "pct", "rua", "ruf", "adkim", "aspf", "fo", "rf", "ri"}


def _check_uris(tag, value, rec_name, add):
    uris = [u.strip() for u in value.split(",")]
    for u in uris:
        if not u:
            add("error", "dmarc-uri", "%s has an empty entry (stray comma)" % tag)
            continue
        if not u.lower().startswith("mailto:"):
            add("warning", "dmarc-uri-scheme", "%s=%s is not a mailto: URI; most receivers only deliver reports by mail" % (tag, safe(u)))
            continue
        body = u[7:]
        size = None
        if "!" in body:
            body, size = body.split("!", 1)
        if not MAILTO_RE.match(body):
            add("error", "dmarc-uri", "%s has an invalid mailto address: %s" % (tag, safe(u)))
            continue
        if size is not None and not re.match(r"^\d+[kKmMgGtT]?$", size):
            add("error", "dmarc-uri", "%s has an invalid size limit '!%s'" % (tag, safe(size)))
        dom = body.rsplit("@", 1)[1].lower()
        if rec_name.lower().startswith("_dmarc."):
            base = rec_name[7:].lower().rstrip(".")
            if dom != base and not dom.endswith("." + base) and not base.endswith("." + dom):
                add("info", "dmarc-external-report",
                    "%s sends reports to %s, outside %s; that domain must publish an authorization record "
                    "(%s._report._dmarc.%s), which cannot be checked offline" % (tag, safe(dom), safe(base), safe(base), safe(dom)))


def lint_dmarc(rec, add):
    text = rec["text"].strip()
    check_string_lengths(rec, add)
    name = rec["name"]
    if name != DEFAULT_NAME and not name.lower().startswith("_dmarc."):
        add("warning", "dmarc-name", "DMARC records are published at _dmarc.<domain>, not at %s" % safe(name))
    pairs, problems = parse_tags(text)
    for p in problems:
        add("error", "dmarc-syntax", "tag without '=': %s" % safe(p))
    tags = {}
    for k, v in pairs:
        if k in tags:
            add("error", "dmarc-duplicate-tag", "tag '%s' appears more than once" % safe(k))
        else:
            tags[k] = v
        if k not in DMARC_KNOWN:
            add("warning", "dmarc-unknown-tag", "unknown tag '%s' is ignored by receivers (typo?)" % safe(k))
    if not pairs or pairs[0][0] != "v":
        add("error", "dmarc-version", "v=DMARC1 must be the first tag")
    elif pairs[0][1] != "DMARC1":
        if pairs[0][1].lower() == "dmarc1":
            add("warning", "dmarc-version", "version value is case-sensitive and must be exactly DMARC1")
        else:
            add("error", "dmarc-version", "version must be DMARC1, got %s" % safe(pairs[0][1]))
    policy = tags.get("p")
    has_rua = bool(tags.get("rua"))
    if policy is None:
        if has_rua:
            add("warning", "dmarc-no-p", "no p= tag; receivers fall back to p=none monitoring only when rua is valid; add p=")
        else:
            add("error", "dmarc-no-p", "required p= tag is missing, so the record is ignored")
    else:
        pl = policy.lower()
        if pl not in ("none", "quarantine", "reject"):
            add("error", "dmarc-bad-value", "p must be none, quarantine or reject, got %s" % safe(policy))
        elif pl == "none":
            add("warning", "dmarc-p-none", "p=none only monitors and blocks nothing; move to quarantine then reject once reports look clean")
        if policy != pl and pl in ("none", "quarantine", "reject"):
            add("info", "dmarc-case", "policy values are case-insensitive but lowercase is the convention")
        if len(pairs) > 1 and pairs[0][0] == "v" and pairs[1][0] != "p":
            add("info", "dmarc-tag-order", "p is conventionally the second tag; some validators require v then p")
    sp = tags.get("sp")
    if sp is not None:
        spl = sp.lower()
        if spl not in ("none", "quarantine", "reject"):
            add("error", "dmarc-bad-value", "sp must be none, quarantine or reject, got %s" % safe(sp))
        elif spl == "none" and policy and policy.lower() in ("quarantine", "reject"):
            add("warning", "dmarc-sp-none", "sp=none leaves subdomains unprotected while the main domain enforces %s" % safe(policy.lower()))
    elif policy is not None:
        add("info", "dmarc-sp-inherits", "no sp= tag: subdomains inherit p=%s" % safe(policy))
    pct = tags.get("pct")
    if pct is not None:
        if not re.match(r"^\d{1,3}$", pct) or int(pct) > 100:
            add("error", "dmarc-bad-value", "pct must be an integer 0-100, got %s" % safe(pct))
        elif int(pct) < 100:
            add("warning", "dmarc-pct", "pct=%s applies the policy to only part of the mail; use 100 when you are done rolling out" % pct)
    if "rua" in tags:
        if tags["rua"]:
            _check_uris("rua", tags["rua"], name, add)
        else:
            add("error", "dmarc-uri", "rua is empty")
            has_rua = False
    if not has_rua:
        add("warning", "dmarc-no-rua", "no rua= address: you will receive no aggregate reports, so you cannot see who sends as your domain")
    if "ruf" in tags:
        if tags["ruf"]:
            _check_uris("ruf", tags["ruf"], name, add)
        else:
            add("error", "dmarc-uri", "ruf is empty")
        add("info", "dmarc-ruf", "ruf (failure reports) is honoured by few receivers and may carry message content; rua is the useful one")
    for tag in ("adkim", "aspf"):
        v = tags.get(tag)
        if v is not None:
            if v.lower() not in ("r", "s"):
                add("error", "dmarc-bad-value", "%s must be r (relaxed) or s (strict), got %s" % (tag, safe(v)))
            elif v.lower() == "s":
                add("info", "dmarc-strict-alignment", "%s=s requires the exact domain to match; subdomain senders will fail" % tag)
    if "adkim" not in tags and "aspf" not in tags:
        add("info", "dmarc-alignment-default", "adkim and aspf are unset: both default to relaxed alignment")
    fo = tags.get("fo")
    if fo is not None:
        for part in fo.split(":"):
            if part.strip() not in ("0", "1", "d", "s"):
                add("error", "dmarc-bad-value", "fo values must be 0, 1, d or s separated by ':', got %s" % safe(part))
                break
    rf = tags.get("rf")
    if rf is not None and rf.lower() not in ("afrf", "iodef"):
        add("error", "dmarc-bad-value", "rf must be afrf, got %s" % safe(rf))
    ri = tags.get("ri")
    if ri is not None and (not re.match(r"^\d+$", ri) or int(ri) == 0 or int(ri) > 4294967295):
        add("error", "dmarc-bad-value", "ri must be a positive 32-bit integer of seconds, got %s" % safe(ri))


# --------------------------------------------------------------------------
# DKIM
# --------------------------------------------------------------------------

def _der_read(b, i):
    if i + 2 > len(b):
        raise ValueError("truncated DER")
    tag = b[i]
    length = b[i + 1]
    j = i + 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4 or j + n > len(b):
            raise ValueError("bad DER length")
        length = int.from_bytes(b[j:j + n], "big")
        j += n
    end = j + length
    if end > len(b):
        raise ValueError("DER length exceeds data")
    return tag, j, end


def rsa_modulus_bits(der):
    """Bit length of the RSA modulus in a DER SubjectPublicKeyInfo or RSAPublicKey."""
    tag, s, e = _der_read(der, 0)
    if tag != 0x30:
        raise ValueError("not a DER SEQUENCE")
    t1, s1, e1 = _der_read(der, s)
    if t1 == 0x30:  # SubjectPublicKeyInfo
        t2, s2, e2 = _der_read(der, s1)
        if t2 != 0x06:
            raise ValueError("missing algorithm OID")
        if der[s2:e2] != bytes.fromhex("2a864886f70d010101"):
            raise ValueError("algorithm is not rsaEncryption")
        t3, s3, e3 = _der_read(der, e1)
        if t3 != 0x03 or e3 - s3 < 2:
            raise ValueError("missing BIT STRING")
        inner = der[s3 + 1:e3]
        it, is_, ie = _der_read(inner, 0)
        if it != 0x30:
            raise ValueError("RSAPublicKey is not a SEQUENCE")
        nt, ns, ne = _der_read(inner, is_)
        if nt != 0x02:
            raise ValueError("modulus is not an INTEGER")
        n = int.from_bytes(inner[ns:ne], "big")
    elif t1 == 0x02:  # bare RSAPublicKey
        n = int.from_bytes(der[s1:e1], "big")
    else:
        raise ValueError("unexpected DER structure")
    if n == 0:
        raise ValueError("zero modulus")
    return n.bit_length()


def lint_dkim(rec, add):
    text = rec["text"].strip()
    check_string_lengths(rec, add)
    name = rec["name"]
    if name != DEFAULT_NAME and "._domainkey." not in name.lower():
        add("warning", "dkim-name", "DKIM keys are published at <selector>._domainkey.<domain>, not at %s" % safe(name))
    pairs, problems = parse_tags(text)
    for p in problems:
        add("error", "dkim-syntax", "tag without '=': %s" % safe(p))
    tags = {}
    for k, v in pairs:
        if k in tags:
            add("error", "dkim-duplicate-tag", "tag '%s' appears more than once" % safe(k))
        else:
            tags[k] = v
        if k not in ("v", "h", "k", "n", "p", "s", "t", "g"):
            add("info", "dkim-unknown-tag", "unknown tag '%s' is ignored by verifiers" % safe(k))
    if "v" in tags:
        if pairs[0][0] != "v":
            add("error", "dkim-version", "v=DKIM1 must be the first tag when present")
        if tags["v"] != "DKIM1":
            add("error", "dkim-version", "version must be DKIM1, got %s" % safe(tags["v"]))
    else:
        add("info", "dkim-no-version", "v=DKIM1 is optional but recommended")
    if "g" in tags:
        add("info", "dkim-g", "g= (granularity) was removed in RFC 6376; verifiers ignore it")
    k = tags.get("k", "rsa").lower()
    if k not in ("rsa", "ed25519"):
        add("warning", "dkim-key-type", "k=%s is not a key type verifiers support (rsa, ed25519)" % safe(k))
    flags = tags.get("t")
    if flags is not None:
        parts = [x.strip().lower() for x in flags.split(":")]
        if "y" in parts:
            add("warning", "dkim-testing", "t=y marks the domain as testing: verifiers may treat failures as no signature; remove it in production")
        if "s" in parts:
            add("info", "dkim-t-s", "t=s forbids subdomain signing with this key")
        for x in parts:
            if x not in ("y", "s"):
                add("info", "dkim-unknown-flag", "unknown t= flag '%s' is ignored" % safe(x))
    h = tags.get("h")
    if h is not None:
        for x in h.split(":"):
            x = x.strip().lower()
            if x == "sha1":
                add("warning", "dkim-sha1", "h=sha1 is deprecated (RFC 8301); allow sha256 only")
            elif x != "sha256":
                add("warning", "dkim-bad-hash", "unknown hash algorithm '%s' in h=" % safe(x))
    s = tags.get("s")
    if s is not None:
        for x in s.split(":"):
            if x.strip().lower() not in ("email", "*"):
                add("warning", "dkim-bad-service", "unknown service type '%s' in s=" % safe(x))
    if "p" not in tags:
        add("error", "dkim-no-p", "required p= tag is missing")
        return
    p = re.sub(r"\s+", "", tags["p"])
    if not p:
        add("warning", "dkim-revoked", "p= is empty: this key is revoked and nothing signed with it will verify")
        return
    try:
        padded = p + "=" * (-len(p) % 4)
        der = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        add("error", "dkim-p-base64", "p= is not valid base64")
        return
    if k == "ed25519":
        if len(der) != 32:
            add("error", "dkim-key-length", "ed25519 public key must decode to 32 bytes, got %d" % len(der))
        else:
            add("info", "dkim-key-length", "ed25519 key (256-bit, strong); not every receiver verifies ed25519 yet, so keep an RSA signature too")
        return
    if k != "rsa":
        return
    try:
        bits = rsa_modulus_bits(der)
    except (ValueError, IndexError) as exc:
        add("error", "dkim-key-parse", "p= does not decode to an RSA public key (%s)" % safe(exc))
        return
    if bits < 1024:
        add("error", "dkim-short-key", "RSA key is %d bits; keys under 1024 bits are broken, use 2048" % bits)
    elif bits < 2048:
        add("warning", "dkim-short-key", "RSA key is %d bits; 2048 bits or more is recommended (RFC 8301 requires 1024 minimum)" % bits)
    else:
        add("info", "dkim-key-length", "RSA key is %d bits" % bits)


# --------------------------------------------------------------------------
# driver
# --------------------------------------------------------------------------

LINTERS = {"spf": lint_spf, "dmarc": lint_dmarc, "dkim": lint_dkim}


def lint_records(records):
    results = []
    for rec in records:
        findings = []
        res = {"name": rec["name"], "type": rec["kind"], "line": rec["line"], "findings": findings}

        def add(sev, code, msg, _f=findings):
            _f.append({"severity": sev, "code": code, "message": msg})

        if rec["kind"] is None:
            if rec["rtype"] == "TXT" and rec["name"] != DEFAULT_NAME:
                add("info", "not-mailauth", "TXT record is not SPF, DMARC or DKIM; ignored")
            else:
                add("info", "unknown-type", "cannot tell the record type; start it with v=spf1, v=DMARC1 or v=DKIM1, or pass --type")
        else:
            LINTERS[rec["kind"]](rec, add)
        results.append(res)
    # duplicate records of the same type at the same name
    groups = {}
    for rec, res in zip(records, results):
        if rec["kind"] in ("spf", "dmarc"):
            groups.setdefault((rec["name"].lower().rstrip("."), rec["kind"]), []).append((rec, res))
    for (name, kind), items in groups.items():
        if len(items) > 1:
            lines = ", ".join(str(r["line"]) for r, _ in items)
            if name == DEFAULT_NAME:
                sev = "warning"
                extra = " (records without a name are grouped; if they belong to different domains, prefix each with its name)"
            else:
                sev = "error"
                extra = ""
            code = "spf-multiple" if kind == "spf" else "dmarc-multiple"
            msg = "%d %s records at the same name (lines %s); %s%s" % (
                len(items), kind.upper(), lines,
                "more than one SPF record is a permerror" if kind == "spf" else "receivers ignore DMARC when there is more than one record",
                extra)
            for _, res in items:
                res["findings"].append({"severity": sev, "code": code, "message": msg})
    return results


def summarize(results):
    counts = {"error": 0, "warning": 0, "info": 0}
    for r in results:
        for f in r["findings"]:
            counts[f["severity"]] += 1
    return counts


def read_source(path):
    """Read at most MAX_INPUT_BYTES from a file path or '-' for stdin."""
    try:
        if path == "-":
            data = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        else:
            with open(path, "rb") as fh:
                data = fh.read(MAX_INPUT_BYTES + 1)
    except OSError as exc:
        raise ValueError("cannot read %s: %s" % (safe(path), safe(exc.strerror or exc)))
    truncated = len(data) > MAX_INPUT_BYTES
    data = data[:MAX_INPUT_BYTES]
    if b"\x00" in data[:4096]:
        raise ValueError("%s looks binary (NUL bytes); expected DNS record text" % safe(path))
    return data.decode("utf-8", errors="replace"), truncated


def format_text(results, counts, notes):
    lines = []
    for r in results:
        label = r["type"].upper() if r["type"] else "?"
        lines.append("%s [%s] line %d" % (safe(r["name"]), label, r["line"]))
        if not r["findings"]:
            lines.append("  OK     no findings")
        for f in sorted(r["findings"], key=lambda x: -SEV_RANK[x["severity"]]):
            lines.append("  %-7s %-24s %s" % (f["severity"].upper(), f["code"], f["message"]))
    for n in notes:
        lines.append("note: " + n)
    lines.append("%d record(s): %d error(s), %d warning(s), %d info" % (
        len(results), counts["error"], counts["warning"], counts["info"]))
    return "\n".join(lines)


def build_parser():
    p = argparse.ArgumentParser(
        prog="mailauth-lint",
        description="Offline linter for SPF, DMARC and DKIM DNS record text. No DNS lookups.",
        epilog="Exit codes: 0 clean, 1 findings at or above --fail-on, 2 usage/input error.",
    )
    p.add_argument("files", nargs="*", help="files with records ('-' for stdin)")
    p.add_argument("-r", "--record", action="append", default=[], metavar="TEXT",
                   help="a record given inline (repeatable); accepts the same line formats as files")
    p.add_argument("--type", choices=["auto", "spf", "dmarc", "dkim"], default="auto",
                   help="force the record type for bare strings (default: detect from v=)")
    p.add_argument("--fail-on", choices=["info", "warning", "error", "never"], default="warning",
                   help="lowest severity that gives exit code 1 (default: warning)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--version", action="version", version="mailauth-lint " + __version__)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    texts = []
    notes = []
    for rec in args.record:
        texts.append(rec)
    files = args.files
    if not files and not args.record:
        files = ["-"]
    for f in files:
        try:
            t, trunc = read_source(f)
        except ValueError as exc:
            print("mailauth-lint: %s" % exc, file=sys.stderr)
            return 2
        if trunc:
            notes.append("%s is larger than %d bytes; only the first part was read" % (safe(f), MAX_INPUT_BYTES))
        texts.append(t)
    records = parse_input("\n".join(texts), args.type)
    if not records:
        print("mailauth-lint: no records found in the input", file=sys.stderr)
        return 2
    results = lint_records(records)
    counts = summarize(results)
    notes.append("offline only: no DNS lookups were made, so includes, redirects, void lookups and report authorizations are not verified")
    if args.json:
        out = {"tool": "mailauth-lint", "version": __version__, "records": results,
               "summary": counts, "notes": notes}
        print(json.dumps(out, indent=2, ensure_ascii=True))
    else:
        print(format_text(results, counts, notes))
    if args.fail_on == "never":
        return 0
    threshold = SEV_RANK[args.fail_on]
    for r in results:
        for f in r["findings"]:
            if SEV_RANK[f["severity"]] >= threshold:
                return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
