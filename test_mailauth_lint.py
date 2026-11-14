import base64
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

import mailauth_lint as m


def run(argv, stdin_text=None):
    out, err = io.StringIO(), io.StringIO()
    old = m.sys.stdin
    if stdin_text is not None:
        m.sys.stdin = io.TextIOWrapper(io.BytesIO(stdin_text.encode("utf-8")))
    try:
        with redirect_stdout(out), redirect_stderr(err):
            try:
                code = m.main(argv)
            except SystemExit as e:
                code = e.code
    finally:
        m.sys.stdin = old
    return code, out.getvalue(), err.getvalue()


def lint(text, typ="auto"):
    return m.lint_records(m.parse_input(text, typ))


def codes(text, typ="auto"):
    res = lint(text, typ)
    return [(f["severity"], f["code"]) for r in res for f in r["findings"]]


def has(text, code, sev=None, typ="auto"):
    return any(c == code and (sev is None or s == sev) for s, c in codes(text, typ))


def der_len(n):
    if n < 128:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag, body):
    return bytes([tag]) + der_len(len(body)) + body


def fake_rsa_key(bits, spki=True):
    n = (1 << (bits - 1)) | 0x1234567 | 1
    nb = n.to_bytes((bits + 7) // 8, "big")
    if nb[0] & 0x80:
        nb = b"\x00" + nb
    rsa = tlv(0x30, tlv(0x02, nb) + tlv(0x02, b"\x01\x00\x01"))
    if not spki:
        return rsa
    alg = tlv(0x30, tlv(0x06, bytes.fromhex("2a864886f70d010101")) + tlv(0x05, b""))
    return tlv(0x30, alg + tlv(0x03, b"\x00" + rsa))


def dkim_txt(bits, extra="", spki=True):
    p = base64.b64encode(fake_rsa_key(bits, spki)).decode()
    body = "v=DKIM1; k=rsa; %sp=%s" % (extra, p)
    chunks = [body[i:i + 200] for i in range(0, len(body), 200)]
    return "s1._domainkey.example.com TXT " + " ".join('"%s"' % c for c in chunks)


class ParseTests(unittest.TestCase):
    def test_full_line(self):
        r = m.parse_input('example.com. 300 IN TXT "v=spf1 -all"')[0]
        self.assertEqual((r["name"], r["kind"], r["text"]), ("example.com.", "spf", "v=spf1 -all"))

    def test_strings_concatenate_without_space(self):
        r = m.parse_input('a.example.com TXT "v=spf1 ip4:192.0.2." "1 -all"')[0]
        self.assertEqual(r["text"], "v=spf1 ip4:192.0.2.1 -all")
        self.assertEqual(len(r["strings"]), 2)

    def test_bare_record_detected(self):
        r = m.parse_input("v=spf1 a mx -all")[0]
        self.assertEqual((r["name"], r["kind"]), (m.DEFAULT_NAME, "spf"))

    def test_bare_spf_not_mistaken_for_named(self):
        r = m.parse_input("v=spf1 a mx -all")[0]
        self.assertEqual(r["rtype"], "TXT")

    def test_comments_and_blank_skipped(self):
        self.assertEqual(len(m.parse_input("# c\n; c\n\nv=spf1 -all\n")), 1)

    def test_force_type(self):
        self.assertEqual(m.parse_input("p=reject", "dmarc")[0]["kind"], "dmarc")

    def test_unknown_txt_ignored(self):
        res = lint('example.com TXT "google-site-verification=abc"')
        self.assertEqual(res[0]["findings"][0]["code"], "not-mailauth")

    def test_escaped_quote(self):
        r = m.parse_input('x.example.com TXT "v=spf1 \\"a\\" -all"')[0]
        self.assertIn('"a"', r["text"])


class SpfTests(unittest.TestCase):
    def test_clean_spf(self):
        c = codes("v=spf1 ip4:192.0.2.0/24 include:_spf.example.net -all")
        self.assertFalse([x for x in c if x[0] in ("error", "warning")])

    def test_plus_all(self):
        self.assertTrue(has("v=spf1 a +all", "spf-plus-all", "error"))

    def test_bare_all_is_plus(self):
        self.assertTrue(has("v=spf1 a all", "spf-plus-all"))

    def test_question_all(self):
        self.assertTrue(has("v=spf1 a ?all", "spf-neutral-all", "warning"))

    def test_softfail_info(self):
        self.assertTrue(has("v=spf1 a ~all", "spf-softfail-all", "info"))

    def test_hardfail_no_note(self):
        self.assertFalse(has("v=spf1 a -all", "spf-softfail-all"))

    def test_ptr_deprecated(self):
        self.assertTrue(has("v=spf1 ptr -all", "spf-ptr", "warning"))

    def test_lookup_limit_exceeded(self):
        inc = " ".join("include:s%d.example.com" % i for i in range(11))
        self.assertTrue(has("v=spf1 %s -all" % inc, "spf-lookup-limit", "error"))

    def test_lookup_exactly_ten_warns(self):
        inc = " ".join("include:s%d.example.com" % i for i in range(10))
        self.assertTrue(has("v=spf1 %s -all" % inc, "spf-lookup-limit", "warning"))

    def test_mixed_mechanisms_counted(self):
        t = "v=spf1 a mx ptr exists:x.example.com include:i.example.com redirect=r.example.com"
        n = [f for r in lint(t) for f in r["findings"] if f["code"] == "spf-lookup-count"][0]
        self.assertIn("6 lookup", n["message"])

    def test_ip_not_counted(self):
        self.assertFalse(has("v=spf1 ip4:192.0.2.1 ip6:2001:db8::/32 -all", "spf-lookup-count"))

    def test_void_lookup_disclaimer(self):
        self.assertTrue(has("v=spf1 include:a.example.com -all", "spf-void-unchecked", "info"))

    def test_multiple_records_error(self):
        t = 'example.com TXT "v=spf1 -all"\nexample.com TXT "v=spf1 a -all"'
        self.assertTrue(has(t, "spf-multiple", "error"))

    def test_multiple_bare_records_only_warning(self):
        self.assertTrue(has("v=spf1 -all\nv=spf1 a -all", "spf-multiple", "warning"))

    def test_different_names_ok(self):
        t = 'a.example.com TXT "v=spf1 -all"\nb.example.com TXT "v=spf1 -all"'
        self.assertFalse(has(t, "spf-multiple"))

    def test_redirect_plus_all(self):
        self.assertTrue(has("v=spf1 redirect=b.example.com -all", "spf-redirect-with-all", "warning"))

    def test_redirect_alone_ok(self):
        self.assertFalse(has("v=spf1 redirect=b.example.com", "spf-no-all"))

    def test_no_all_warns(self):
        self.assertTrue(has("v=spf1 a", "spf-no-all", "warning"))

    def test_after_all(self):
        self.assertTrue(has("v=spf1 -all a", "spf-after-all", "warning"))

    def test_syntax_unknown_term(self):
        self.assertTrue(has("v=spf1 bogus -all", "spf-syntax", "error"))

    def test_syntax_include_equals(self):
        self.assertTrue(has("v=spf1 include=x.example.com -all", "spf-syntax", "error"))

    def test_syntax_bad_ip4(self):
        self.assertTrue(has("v=spf1 ip4:999.1.1.1 -all", "spf-syntax", "error"))

    def test_syntax_bad_cidr(self):
        self.assertTrue(has("v=spf1 a/33 -all", "spf-syntax", "error"))

    def test_syntax_include_missing_domain(self):
        self.assertTrue(has("v=spf1 include: -all", "spf-syntax", "error"))

    def test_broad_ip4(self):
        self.assertTrue(has("v=spf1 ip4:10.0.0.0/8 -all", "spf-broad-ip", "warning"))

    def test_wrong_version(self):
        self.assertTrue(has("v=spf2 a -all", "spf-version", typ="spf"))

    def test_double_redirect(self):
        self.assertTrue(has("v=spf1 redirect=a.example.com redirect=b.example.com", "spf-multiple-redirect"))

    def test_string_too_long_quoted(self):
        t = 'example.com TXT "v=spf1 ip4:192.0.2.1 %s -all"' % ("a" * 260)
        self.assertTrue(has(t, "string-too-long", "error"))

    def test_split_strings_ok(self):
        s = "v=spf1 " + " ".join("ip4:192.0.2.%d" % i for i in range(1, 40)) + " -all"
        t = "example.com TXT " + " ".join('"%s"' % s[i:i + 200] for i in range(0, len(s), 200))
        self.assertFalse(has(t, "string-too-long"))

    def test_total_length_guidance(self):
        s = " ".join("ip4:192.0.2.%d" % i for i in range(1, 60))
        t = 'example.com TXT "v=spf1 %s" "-all"' % s
        self.assertTrue(has(t, "record-long", "warning"))

    def test_duplicate_include(self):
        self.assertTrue(has("v=spf1 include:a.example.com include:a.example.com -all", "spf-duplicate-include"))

    def test_spf_rr_type(self):
        self.assertTrue(has('example.com SPF "v=spf1 -all"', "spf-rr-type"))

    def test_unknown_modifier_info(self):
        self.assertTrue(has("v=spf1 foo=bar -all", "spf-unknown-modifier", "info"))


class DmarcTests(unittest.TestCase):
    GOOD = "_dmarc.example.com TXT \"v=DMARC1; p=reject; rua=mailto:r\x40example.com; adkim=r; aspf=r\""

    def test_good_has_no_warnings(self):
        c = codes(self.GOOD)
        self.assertFalse([x for x in c if x[0] != "info"])

    def test_p_none(self):
        self.assertTrue(has("v=DMARC1; p=none; rua=mailto:r\x40example.com", "dmarc-p-none", "warning"))

    def test_missing_rua(self):
        self.assertTrue(has("v=DMARC1; p=reject", "dmarc-no-rua", "warning"))

    def test_pct_below_100(self):
        self.assertTrue(has("v=DMARC1; p=reject; pct=25; rua=mailto:r\x40example.com", "dmarc-pct", "warning"))

    def test_pct_invalid(self):
        self.assertTrue(has("v=DMARC1; p=reject; pct=150", "dmarc-bad-value", "error"))
        self.assertTrue(has("v=DMARC1; p=reject; pct=abc", "dmarc-bad-value", "error"))

    def test_missing_p_error(self):
        self.assertTrue(has("v=DMARC1; ri=60", "dmarc-no-p", "error"))

    def test_missing_p_with_rua_warns(self):
        self.assertTrue(has("v=DMARC1; rua=mailto:r\x40example.com", "dmarc-no-p", "warning"))

    def test_invalid_policy(self):
        self.assertTrue(has("v=DMARC1; p=block", "dmarc-bad-value", "error"))

    def test_sp_invalid_and_none(self):
        self.assertTrue(has("v=DMARC1; p=reject; sp=x", "dmarc-bad-value"))
        self.assertTrue(has("v=DMARC1; p=reject; sp=none", "dmarc-sp-none", "warning"))

    def test_alignment_values(self):
        self.assertTrue(has("v=DMARC1; p=reject; adkim=q", "dmarc-bad-value"))
        self.assertTrue(has("v=DMARC1; p=reject; aspf=s", "dmarc-strict-alignment", "info"))

    def test_unknown_tag(self):
        self.assertTrue(has("v=DMARC1; p=reject; foo=1", "dmarc-unknown-tag", "warning"))

    def test_duplicate_tag(self):
        self.assertTrue(has("v=DMARC1; p=reject; p=none", "dmarc-duplicate-tag", "error"))

    def test_version_first(self):
        self.assertTrue(has("p=reject; v=DMARC1", "dmarc-version", "error", typ="dmarc"))

    def test_version_lowercase_value(self):
        self.assertTrue(has("v=DMARC1; p=reject".replace("DMARC1", "dmarc1"), "dmarc-version", "warning"))

    def test_rua_bad_uri(self):
        self.assertTrue(has("v=DMARC1; p=reject; rua=r\x40example.com", "dmarc-uri-scheme", "warning"))
        self.assertTrue(has("v=DMARC1; p=reject; rua=mailto:not-an-address", "dmarc-uri", "error"))
        self.assertTrue(has("v=DMARC1; p=reject; rua=mailto:a\x40example.com,", "dmarc-uri", "error"))

    def test_rua_size_suffix(self):
        self.assertFalse(has("v=DMARC1; p=reject; rua=mailto:a\x40example.com!10m", "dmarc-uri"))
        self.assertTrue(has("v=DMARC1; p=reject; rua=mailto:a\x40example.com!big", "dmarc-uri", "error"))

    def test_rua_multiple(self):
        self.assertFalse(has("v=DMARC1; p=reject; rua=mailto:a\x40example.com, mailto:b\x40example.com", "dmarc-uri"))

    def test_external_report_note(self):
        t = '_dmarc.example.com TXT "v=DMARC1; p=reject; rua=mailto:r\x40example.net"'
        self.assertTrue(has(t, "dmarc-external-report", "info"))

    def test_wrong_name(self):
        self.assertTrue(has('example.com TXT "v=DMARC1; p=reject"', "dmarc-name", "warning"))

    def test_fo_rf_ri(self):
        self.assertTrue(has("v=DMARC1; p=reject; fo=2", "dmarc-bad-value"))
        self.assertTrue(has("v=DMARC1; p=reject; ri=0", "dmarc-bad-value"))
        self.assertFalse(has("v=DMARC1; p=reject; fo=0:1:d:s; ri=86400", "dmarc-bad-value"))

    def test_tag_without_equals(self):
        self.assertTrue(has("v=DMARC1; p=reject; oops", "dmarc-syntax", "error"))

    def test_multiple_dmarc_records(self):
        t = '_dmarc.example.com TXT "v=DMARC1; p=none"\n_dmarc.example.com TXT "v=DMARC1; p=reject"'
        self.assertTrue(has(t, "dmarc-multiple", "error"))


class DkimTests(unittest.TestCase):
    def test_2048_ok(self):
        c = codes(dkim_txt(2048))
        self.assertFalse([x for x in c if x[0] in ("error", "warning")])
        self.assertTrue(has(dkim_txt(2048), "dkim-key-length"))

    def test_1024_warns(self):
        self.assertTrue(has(dkim_txt(1024), "dkim-short-key", "warning"))

    def test_512_error(self):
        self.assertTrue(has(dkim_txt(512), "dkim-short-key", "error"))

    def test_bare_rsa_public_key_der(self):
        self.assertTrue(has(dkim_txt(1024, spki=False), "dkim-short-key", "warning"))

    def test_modulus_bits_exact(self):
        self.assertEqual(m.rsa_modulus_bits(fake_rsa_key(2048)), 2048)
        self.assertEqual(m.rsa_modulus_bits(fake_rsa_key(1000)), 1000)

    def test_4096(self):
        self.assertFalse(has(dkim_txt(4096), "dkim-short-key"))

    def test_revoked(self):
        self.assertTrue(has('s1._domainkey.example.com TXT "v=DKIM1; k=rsa; p="', "dkim-revoked", "warning"))

    def test_missing_p(self):
        self.assertTrue(has('s1._domainkey.example.com TXT "v=DKIM1; k=rsa"', "dkim-no-p", "error"))

    def test_testing_flag(self):
        self.assertTrue(has(dkim_txt(2048, extra="t=y; "), "dkim-testing", "warning"))

    def test_strict_flag_info(self):
        self.assertTrue(has(dkim_txt(2048, extra="t=s; "), "dkim-t-s", "info"))

    def test_key_type(self):
        self.assertTrue(has("v=DKIM1; k=dsa; p=QUJD", "dkim-key-type", "warning"))

    def test_ed25519_length(self):
        good = base64.b64encode(bytes(range(32))).decode()
        self.assertFalse(has("v=DKIM1; k=ed25519; p=%s" % good, "dkim-key-length", "error"))
        self.assertTrue(has("v=DKIM1; k=ed25519; p=QUJD", "dkim-key-length", "error"))

    def test_bad_base64(self):
        self.assertTrue(has("v=DKIM1; k=rsa; p=!!!notbase64", "dkim-p-base64", "error"))

    def test_garbage_der(self):
        p = base64.b64encode(b"\x00\x01\x02garbage").decode()
        self.assertTrue(has("v=DKIM1; k=rsa; p=" + p, "dkim-key-parse", "error"))

    def test_truncated_der_no_crash(self):
        p = base64.b64encode(fake_rsa_key(2048)[:40]).decode()
        self.assertTrue(has("v=DKIM1; k=rsa; p=" + p, "dkim-key-parse", "error"))

    def test_whitespace_folded_key(self):
        p = base64.b64encode(fake_rsa_key(1024)).decode()
        folded = '" "'.join(p[i:i + 50] for i in range(0, len(p), 50))
        t = 's1._domainkey.example.com TXT "v=DKIM1; k=rsa; p=%s"' % folded
        self.assertTrue(has(t, "dkim-short-key", "warning"))

    def test_sha1_deprecated(self):
        self.assertTrue(has(dkim_txt(2048, extra="h=sha1; "), "dkim-sha1", "warning"))

    def test_name_check(self):
        t = 'example.com TXT "v=DKIM1; p=QUJD"'
        self.assertTrue(has(t, "dkim-name", "warning"))

    def test_version_must_be_first(self):
        self.assertTrue(has("k=rsa; v=DKIM1; p=", "dkim-version", "error", typ="dkim"))

    def test_string_too_long(self):
        p = "A" * 400
        self.assertTrue(has('s1._domainkey.example.com TXT "v=DKIM1; p=%s"' % p, "string-too-long", "error"))


class CliTests(unittest.TestCase):
    def test_clean_exit_0(self):
        code, out, _ = run(["-r", "v=spf1 -all", "--fail-on", "warning"])
        self.assertEqual(code, 0)

    def test_warning_exit_1(self):
        code, _, _ = run(["-r", "v=spf1 a ?all"])
        self.assertEqual(code, 1)

    def test_fail_on_error_ignores_warnings(self):
        code, _, _ = run(["-r", "v=spf1 a ?all", "--fail-on", "error"])
        self.assertEqual(code, 0)

    def test_fail_on_error_triggers(self):
        code, _, _ = run(["-r", "v=spf1 a +all", "--fail-on", "error"])
        self.assertEqual(code, 1)

    def test_fail_on_never(self):
        code, _, _ = run(["-r", "v=spf1 a +all", "--fail-on", "never"])
        self.assertEqual(code, 0)

    def test_stdin(self):
        code, out, _ = run(["-"], stdin_text='example.com TXT "v=spf1 +all"\n')
        self.assertEqual(code, 1)
        self.assertIn("spf-plus-all", out)

    def test_file_input_and_json(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "r.txt")
            with open(p, "w") as fh:
                fh.write('example.com TXT "v=spf1 +all"\n')
            code, out, _ = run([p, "--json"])
        data = json.loads(out)
        self.assertEqual(code, 1)
        self.assertEqual(data["summary"]["error"], 1)
        self.assertEqual(data["records"][0]["type"], "spf")

    def test_missing_file_exit_2(self):
        code, _, err = run(["/nonexistent/path/x.txt"])
        self.assertEqual(code, 2)
        self.assertIn("cannot read", err)

    def test_empty_input_exit_2(self):
        code, _, _ = run(["-"], stdin_text="\n# only comment\n")
        self.assertEqual(code, 2)

    def test_bad_option_exit_2(self):
        code, _, _ = run(["--fail-on", "bogus"])
        self.assertEqual(code, 2)

    def test_type_flag_bare(self):
        code, out, _ = run(["--type", "dmarc", "-r", "p=reject"])
        self.assertIn("dmarc-version", out)
        self.assertEqual(code, 1)

    def test_binary_file_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "b.bin")
            with open(p, "wb") as fh:
                fh.write(b"\x00\x01\x02" * 100)
            code, _, err = run([p])
        self.assertEqual(code, 2)
        self.assertIn("binary", err)

    def test_invalid_utf8_no_crash(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "r.txt")
            with open(p, "wb") as fh:
                fh.write(b'example.com TXT "v=spf1 \xff\xfe -all"\n')
            code, out, _ = run([p])
        self.assertEqual(code, 1)

    def test_control_chars_escaped_in_output(self):
        txt = 'example.com TXT "v=spf1 \x1b[31mbad -all"'
        code, out, _ = run(["-"], stdin_text=txt)
        self.assertNotIn("\x1b", out)
        self.assertIn("\\x1b", out)

    def test_bidi_in_record_escaped(self):
        txt = 'example.com TXT "v=spf1 ' + chr(0x202E) + 'bad -all"'
        code, out, _ = run(["-"], stdin_text=txt)
        self.assertNotIn(chr(0x202E), out)

    def test_huge_input_capped(self):
        old = m.MAX_INPUT_BYTES
        m.MAX_INPUT_BYTES = 2000
        try:
            with tempfile.TemporaryDirectory() as d:
                p = os.path.join(d, "big.txt")
                with open(p, "w") as fh:
                    fh.write(("v=spf1 a -all\n") * 5000)
                code, out, _ = run([p])
        finally:
            m.MAX_INPUT_BYTES = old
        self.assertIn("only the first part", out)

    def test_many_records_capped(self):
        recs = m.parse_input("v=spf1 -all\n" * (m.MAX_RECORDS + 50))
        self.assertEqual(len(recs), m.MAX_RECORDS)

    def test_long_garbage_line_no_crash(self):
        res = lint("v=spf1 " + "x" * 100000)
        self.assertTrue(res)

    def test_summary_line(self):
        _, out, _ = run(["-r", "v=spf1 -all"])
        self.assertIn("1 record(s)", out)

    def test_offline_note_present(self):
        _, out, _ = run(["-r", "v=spf1 -all"])
        self.assertIn("no DNS lookups", out)

    def test_directory_arg_exit_2(self):
        with tempfile.TemporaryDirectory() as d:
            code, _, _ = run([d])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
