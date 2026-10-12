"""Unit tests for pps.secrets, the shared secret scanner.

Fully offline, stdlib only. Run with:
    python3 -m unittest discover -s tests -v

Every "secret" here is fake and built from fragments at runtime, so this file
itself contains no secret-shaped strings (GitHub push protection and our own
scanners would otherwise flag it).
"""

import base64
import dataclasses
import logging
import os
import subprocess
import sys
import time
import unittest
import urllib.parse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from pps import secrets  # noqa: E402
from pps.secrets import Finding, find, redact  # noqa: E402

# ---- fake tokens, assembled so no secret-shaped literal is in the source ----
AWS = "AKIA" + "IOSFODNN7EXAMPLE"
GH = "gh" + "p_" + "a" * 36
GH_PAT = "github" + "_pat_" + "A1b2C3d4E5f6G7h8I9j0K1"
GITLAB = "glpat" + "-" + "x" * 20
SLACK_B = "xox" + "b-1234567890-abcdefghij"
SLACK_APP = "xa" + "pp-1-A012345-1234567890-abcdefghijklmnop"
SLACK_HOOK = "hooks.slack" + ".com/services/T0123ABCD/B0123ABCD/abcDEF123456xyz"
ANT = "sk-" + "ant-" + "a" * 30
OAI = "sk-" + "a" * 30
OAI_PROJ = "sk-" + "proj-" + "Ab1" * 10
CLERK_SK = "sk_" + "live_" + "A1b2C3d4E5f6G7h8I9j0K1"
CLERK_SK_TEST = "sk_" + "test_" + "A1b2C3d4E5f6G7h8I9j0K1"
PK_LIVE = "pk_" + "live_" + "A1b2C3d4E5f6G7h8I9j0K1"
RK_LIVE = "rk_" + "live_" + "A1b2C3d4E5f6G7h8I9j0K1"
GOOGLE = "AI" + "za" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"
NPM = "npm" + "_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
JWT_STRICT = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
              "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PYb9EmzYuZE")
JWT_SHORT = "eyJhbGciOiJub25lIn0." "eyJzdWIiOiJ4In0." "c2lnbmF0dXJlMTIz"
PEM = ("-----BEGIN RSA " "PRIVATE KEY-----\nMIIBogIBAAJBAKfakebody\n-----END RSA " "PRIVATE KEY-----")
PGP = "-----BEGIN PGP " "PRIVATE KEY BLOCK-----\nfakebody\n-----END PGP " "PRIVATE KEY BLOCK-----"
DB_PW = "Zr8Kq2Lm5Nv7Xc3B"
VALUE = "Qx7fT2mZp9LwR4vK8sN3bY6hJ1cD5gE0"   # a fake known secret


def labels(text, known=None, **kw):
    return [f.label for f in find(text, known, **kw)]


class PatternTests(unittest.TestCase):
    """One case per shape: find() names it, redact() marks it."""

    SHAPES = [
        ("private-key", PEM),
        ("private-key", PGP),
        ("slack-token", SLACK_B),
        ("slack-token", "xoxa-1234567890-abcdefghij"),
        ("slack-token", "xoxp-1234567890-abcdefghij"),
        ("slack-token", "xoxo-1234567890-abcdefghij"),
        ("slack-app-token", SLACK_APP),
        ("slack-webhook", SLACK_HOOK),
        ("aws-key-id", AWS),
        ("aws-key-id", "ASIA" + "IOSFODNN7EXAMPLE"),
        ("github-token", GH),
        ("github-token", "gh" + "s_" + "B" * 40),
        ("github-pat", GH_PAT),
        ("gitlab-token", GITLAB),
        ("jwt", JWT_STRICT),
        ("jwt", JWT_SHORT),
        ("anthropic-key", ANT),
        ("anthropic-key", "sk-" + "ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"),
        ("openai-key", OAI),
        ("openai-key", OAI_PROJ),
        ("clerk-or-stripe-secret-key", CLERK_SK),
        ("clerk-or-stripe-secret-key", CLERK_SK_TEST),
        ("live-publishable-key", PK_LIVE),
        ("stripe-restricted-key", RK_LIVE),
        ("google-api-key", GOOGLE),
        ("npm-token", NPM),
    ]

    def test_every_shape_is_found_and_redacted(self):
        for label, token in self.SHAPES:
            with self.subTest(label=label, token=token[:12]):
                text = f"before {token} after"
                found = find(text)
                self.assertEqual([f.label for f in found], [label])
                clean, got = redact(text)
                self.assertNotIn(token, clean)
                self.assertIn(f"[redacted:{label}]", clean)
                self.assertTrue(clean.startswith("before ") and clean.endswith(" after"))
                self.assertEqual(got, [label])

    def test_every_rule_label_has_a_case(self):
        covered = {label for label, _ in self.SHAPES} | {
            "keyish-assignment", "database-url-with-password", "high-entropy-assignment"}
        self.assertEqual(covered, set(secrets.PATTERN_LABELS))

    def test_anthropic_key_is_not_mislabelled_openai(self):
        self.assertEqual(labels(f"k {ANT}"), ["anthropic-key"])
        clean, got = redact(f"k {ANT} and {OAI}")
        self.assertEqual(clean, "k [redacted:anthropic-key] and [redacted:openai-key]")
        self.assertEqual(got, ["anthropic-key", "openai-key"])

    def test_private_key_without_end_marker_is_redacted_to_the_end(self):
        text = "x\n-----BEGIN OPENSSH " "PRIVATE KEY-----\nb3BlbnNzaA==\nmore"
        clean, got = redact(text)
        self.assertEqual(clean, "x\n[redacted:private-key]")
        self.assertEqual(got, ["private-key"])

    def test_private_key_block_includes_body_and_end(self):
        clean, _ = redact(f"a\n{PEM}\nb")
        self.assertEqual(clean, "a\n[redacted:private-key]\nb")

    def test_public_key_and_certificate_are_not_private_keys(self):
        self.assertEqual(labels("-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----"), [])
        self.assertEqual(labels("-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----"), [])

    def test_shape_adjacent_to_non_ascii_letter_still_found(self):
        self.assertEqual(labels("é" + AWS + "é"), ["aws-key-id"])

    def test_no_false_positives_on_ordinary_text_and_code(self):
        benign = [
            "Just a normal reply with no secrets in it at all.",
            "const t = process.env.CLERK_SECRET_KEY;",
            'process.env.CLERK_SECRET_KEY = "sk_test_x";',
            'const u = "postgres://postgres:test@127.0.0.1:5432/app";',
            'const tokenUrl = "/api/auth/token-refresh-2";',
            'const sha = "0123456789abcdef0123456789abcdef01234567";',
            "see the task-12345678901234567890123 ticket",       # contains 'sk-' inside a word
            "pk_test_" + "A1b2C3d4E5f6G7h8I9j0K1",               # test publishable keys are public
            "AKIA-not-a-key and ASIA short",
            "-----BEGIN CERTIFICATE-----",
            'password = "' + "a" * 5 + '"',
            'token_url = "https://example.com/oauth/token/refresh/endpoint"',
            "api_key=<your-api-key-goes-here>",
            "ghp_short",
            "xoxb-short",
        ]
        for text in benign:
            with self.subTest(text=text[:40]):
                self.assertEqual(find(text), [])
                self.assertEqual(redact(text), (text, []))


class AssignmentTests(unittest.TestCase):
    def test_keyish_assignment_keeps_key_separator_and_quote(self):
        clean, got = redact('config: api_key="abcdefghijklmnopqrstuvwxyz" done')
        self.assertEqual(clean, 'config: api_key="[redacted]" done')
        self.assertEqual(got, ["keyish-assignment"])

    def test_keyish_assignment_colon_without_quotes(self):
        clean, got = redact("auth_token: abcdefghijklmnopqrstuvwxyz1234 in config")
        self.assertEqual(clean, "auth_token: [redacted] in config")
        self.assertEqual(got, ["keyish-assignment"])

    def test_keyish_assignment_listed_once_per_match(self):
        clean, got = redact('password=abcdefghijklmnop1 and client_secret: "zyxwvutsrqponmlk2"')
        self.assertEqual(got, ["keyish-assignment", "keyish-assignment"])
        self.assertEqual(clean, 'password=[redacted] and client_secret: "[redacted]"')

    def test_ignore_placeholders_for_source_code_scans(self):
        for text in ('const password = "change-me-please-1234";', "password: ${DB_PASSWORD_VALUE_X}",
                     "api_key=<your-api-key-goes-here>", "password = process.env.DATABASE_PASSWORD",
                     "api_key: https://example.com/keys/abcdef0123456789"):
            with self.subTest(text=text):
                self.assertEqual(find(text, ignore_placeholders=True), [])
        # chat default: still redacted (slackcc behaviour)
        self.assertEqual(labels('const password = "change-me-please-1234";'), ["keyish-assignment"])
        # a real-looking value is caught either way
        self.assertEqual(labels(f"password={VALUE}", ignore_placeholders=True), ["keyish-assignment"])
        self.assertEqual(redact('password = "change-me-please-1234"', ignore_placeholders=True),
                         ('password = "change-me-please-1234"', []))

    def test_keyish_is_case_insensitive_and_needs_16_chars(self):
        self.assertEqual(labels("API_KEY = ABCDEFGHIJKLMNOP"), ["keyish-assignment"])
        self.assertEqual(labels("password = short"), [])

    def test_token_inside_assignment_keeps_its_specific_label(self):
        clean, got = redact(f"api_key={ANT}")
        self.assertEqual(clean, "api_key=[redacted:anthropic-key]")
        self.assertEqual(got, ["anthropic-key"])

    def test_database_url_password_only_is_redacted(self):
        text = f"DATABASE_URL=postgres://app:{DB_PW}@db:5432/app"
        self.assertEqual(labels(text), ["database-url-with-password"])
        clean, got = redact(text)
        self.assertEqual(clean, "DATABASE_URL=postgres://app:[redacted:database-url-with-password]@db:5432/app")
        self.assertEqual(got, ["database-url-with-password"])

    def test_database_url_with_obvious_placeholder_password_is_left_alone(self):
        self.assertEqual(labels("postgres://app:changeme-please@db/app"), [])
        self.assertEqual(labels("postgres://postgres:test@127.0.0.1:5432/app"), [])

    def test_other_database_schemes(self):
        self.assertEqual(labels(f"mongodb+srv://u:{DB_PW}@cluster/db"), ["database-url-with-password"])
        self.assertEqual(labels(f"redis://:{DB_PW}@cache:6379"), ["database-url-with-password"])

    def test_high_entropy_quoted_assignment(self):
        text = 'const apiKey_ = "q8W3eR5tY7uI9oP2aS4dF6gH";'
        self.assertEqual(labels(text), ["high-entropy-assignment"])
        clean, _ = redact(text)
        self.assertEqual(clean, 'const apiKey_ = "[redacted:high-entropy-assignment]";')

    def test_high_entropy_bare_env_line(self):
        text = f"export SESSION_TOKEN={VALUE}\nOTHER=1\n"
        self.assertEqual(labels(text), ["high-entropy-assignment"])
        clean, _ = redact(text)
        self.assertEqual(clean, "export SESSION_TOKEN=[redacted:high-entropy-assignment]\nOTHER=1\n")

    def test_high_entropy_rejects_words_and_identifiers(self):
        for text in ('token = "just-a-long-descriptive-name"',        # no digits
                     'secret = "0000000000000000000000000000"',        # no letters
                     'token = "config.settings.tokenValue1"',          # dotted identifier
                     'password: "xxxxxxxxxxxxxxxx1"',                  # placeholder
                     'api_key = "aaaaaaaaaaaaaaaaaaaa1"'):             # low entropy
            with self.subTest(text=text):
                self.assertNotIn("high-entropy-assignment", labels(text))


class KnownValueTests(unittest.TestCase):
    K = {"MY_SECRET": VALUE}

    def test_exact_value(self):
        text = f"the value {VALUE} is here"
        (f,) = find(text, self.K)
        self.assertEqual((f.label, f.var, f.form), ("own-secret", "MY_SECRET", "exact"))
        self.assertEqual(text[f.start:f.end], VALUE)
        clean, got = redact(text, self.K)
        self.assertEqual(clean, "the value [redacted:MY_SECRET] is here")
        self.assertEqual(got, ["own-secret:MY_SECRET"])

    def test_every_occurrence_is_redacted_but_the_var_is_listed_once(self):
        clean, got = redact(f"{VALUE} and {VALUE}", self.K)
        self.assertEqual(clean, "[redacted:MY_SECRET] and [redacted:MY_SECRET]")
        self.assertEqual(got, ["own-secret:MY_SECRET"])
        self.assertEqual(len(find(f"{VALUE} and {VALUE}", self.K)), 2)

    def test_encoded_forms(self):
        raw = VALUE.encode()
        forms = {
            "hex": raw.hex(),
            "hex-upper": raw.hex().upper(),
            "base64": base64.b64encode(raw).decode(),
            "base64-nopad": base64.b64encode(raw).decode().rstrip("="),
            "urlsafe": base64.urlsafe_b64encode(raw).decode(),
            "urlencoded": urllib.parse.quote("pa ss/wo+rd&x=y;z" + VALUE, safe=""),
        }
        k = {"V": VALUE}
        for name, enc in forms.items():
            with self.subTest(form=name):
                text = f"leak: {enc} end"
                if name == "urlencoded":
                    k = {"V": "pa ss/wo+rd&x=y;z" + VALUE}
                got = find(text, k)
                self.assertEqual([(f.label, f.var) for f in got], [("own-secret", "V")])
                clean, labs = redact(text, k)
                self.assertEqual(clean, "leak: [redacted:V] end")
                self.assertEqual(labs, ["own-secret:V"])

    def test_value_embedded_in_larger_base64_at_every_alignment(self):
        for pad in range(3):
            with self.subTest(pad=pad):
                blob = base64.b64encode(b"x" * pad + VALUE.encode() + b"tail-bytes").decode()
                self.assertEqual([f.var for f in find(blob, self.K)], ["MY_SECRET"])
                blob = base64.urlsafe_b64encode(b"a" * pad + VALUE.encode() + b"\xff\xfe!").decode()
                self.assertEqual([f.var for f in find(blob, self.K)], ["MY_SECRET"])

    def test_short_and_empty_values_are_ignored(self):
        known = {"EMPTY": "", "SHORT": "abc123", "SEVEN": "1234567", "NONE": None}
        text = "abc123 1234567 and 616263313233 (hex of abc123)"
        self.assertEqual(find(text, known), [])
        self.assertEqual(redact(text, known), (text, []))

    def test_minimum_length_is_eight_by_default_and_configurable(self):
        self.assertEqual(secrets.MIN_KNOWN_LEN, 8)
        self.assertEqual(len(find("xx 12345678 xx", {"E": "12345678"})), 1)
        self.assertEqual(find("xx 12345678 xx", {"E": "12345678"}, min_known_len=9), [])

    def test_surrounding_whitespace_in_a_value_is_ignored(self):
        self.assertEqual(len(find(f"a {VALUE} b", {"V": f"{VALUE}\n"})), 1)

    def test_longest_first_so_a_whole_value_wins_over_a_contained_one(self):
        known = {"SHORT": "supersecret", "LONG": "supersecret-and-more"}
        clean, got = redact("x supersecret-and-more y supersecret z", known)
        self.assertEqual(clean, "x [redacted:LONG] y [redacted:SHORT] z")
        self.assertEqual(got, ["own-secret:SHORT", "own-secret:LONG"])  # mapping order

    def test_known_value_beats_a_shape_inside_it(self):
        tok = SLACK_B + "-unique"
        clean, got = redact(f"t {tok}", {"SLACK_BOT_TOKEN": tok})
        self.assertEqual(clean, "t [redacted:SLACK_BOT_TOKEN]")
        self.assertEqual(got, ["own-secret:SLACK_BOT_TOKEN"])

    def test_known_value_that_is_also_a_shape_is_labelled_by_var_not_shape(self):
        self.assertEqual([f.label for f in find(AWS, {"K": AWS})], ["own-secret"])

    def test_allow_list_suppresses_public_values(self):
        dummy = "sk-" + "ant-oat01-cell-dummy-no-real-credential-present-000000000000"
        self.assertEqual(len(find(dummy)), 1)
        self.assertEqual(find(dummy, allow=[dummy]), [])
        self.assertEqual(find(dummy, {"CELL": dummy}, allow=[dummy]), [])
        self.assertEqual(find(dummy.encode(), allow=[dummy.encode()]), [])
        self.assertEqual(redact(f"x {dummy}", allow=[dummy]), (f"x {dummy}", []))

    def test_known_value_for_unrelated_text_does_nothing(self):
        text = "nothing to see here"
        self.assertEqual(redact(text, self.K), (text, []))


class BytesTests(unittest.TestCase):
    def test_find_in_bytes_uses_byte_offsets(self):
        data = b"\x00\x01PNG\n" + AWS.encode() + b"\xff\x00"
        (f,) = find(data)
        self.assertEqual((f.label, f.start, f.end, f.line), ("aws-key-id", 6, 6 + len(AWS), 2))
        self.assertEqual(data[f.start:f.end], AWS.encode())

    def test_known_value_inside_binary(self):
        data = b"\x00\x01PNG" + VALUE.encode() + b"\x00\xff"
        self.assertEqual([f.var for f in find(data, {"V": VALUE})], ["V"])
        self.assertEqual([f.var for f in find(data, {"V": VALUE.encode()})], ["V"])

    def test_non_utf8_known_value(self):
        value = bytes(range(128, 148))
        data = b"junk" + value + b"junk"
        (f,) = find(data, {"BIN": value})
        self.assertEqual((f.var, f.start, f.end), ("BIN", 4, 4 + len(value)))
        hexed = value.hex().encode()
        self.assertEqual([x.var for x in find(b"x" + hexed, {"BIN": value})], ["BIN"])
        # a str haystack can still catch the encoded forms of a non-text value
        self.assertEqual([x.var for x in find("h " + value.hex(), {"BIN": value})], ["BIN"])

    def test_non_ascii_str_value(self):
        value = "pässwörd-ünïcode-123"
        self.assertEqual([f.var for f in find(f"x {value} y", {"U": value})], ["U"])
        self.assertEqual([f.var for f in find(f"x {value} y".encode(), {"U": value})], ["U"])
        self.assertEqual([f.var for f in find(urllib.parse.quote(value, safe=""), {"U": value})], ["U"])

    def test_redact_bytes_returns_bytes(self):
        clean, got = redact(b"a " + ANT.encode() + b" b")
        self.assertIsInstance(clean, bytes)
        self.assertEqual(clean, b"a [redacted:anthropic-key] b")
        self.assertEqual(got, ["anthropic-key"])
        same = b"nothing here"
        self.assertEqual(redact(same), (same, []))

    def test_str_and_bytes_agree_on_ascii(self):
        text = f"a\nb {SLACK_B}\nc {GH} password=abcdefghijklmnop1"
        self.assertEqual(find(text), find(text.encode()))
        self.assertEqual(redact(text)[0], redact(text.encode())[0].decode())

    def test_wrong_type_is_rejected(self):
        with self.assertRaises(TypeError):
            find(123)
        with self.assertRaises(TypeError):
            redact(None)


class FindingTests(unittest.TestCase):
    def test_positions_and_lines(self):
        text = f"line one\nline two {AWS}\n\nline four {GH}"
        a, b = find(text)
        self.assertEqual((a.label, a.line, text[a.start:a.end]), ("aws-key-id", 2, AWS))
        self.assertEqual((b.label, b.line, text[b.start:b.end]), ("github-token", 4, GH))

    def test_findings_are_in_position_order(self):
        text = f"{GH} then {AWS} then {SLACK_B}"
        got = find(text)
        self.assertEqual([f.start for f in got], sorted(f.start for f in got))
        self.assertEqual([f.label for f in got], ["github-token", "aws-key-id", "slack-token"])

    def test_finding_has_no_field_that_can_hold_the_value(self):
        names = {f.name for f in dataclasses.fields(Finding)}
        self.assertEqual(names, {"label", "start", "end", "line", "var", "form"})
        for f in dataclasses.fields(Finding):
            self.assertIn(f.type, ("str", "int", "str | None"), f.name)

    def test_finding_is_immutable_and_hashable(self):
        f = find(AWS)[0]
        with self.assertRaises(dataclasses.FrozenInstanceError):
            f.label = "x"
        self.assertEqual(len({f, f}), 1)

    def test_value_never_in_repr_or_str_of_any_finding(self):
        values = [t for _, t in PatternTests.SHAPES] + [DB_PW, VALUE]
        text = "\n".join(values) + f"\npostgres://app:{DB_PW}@db/app\npassword={VALUE}"
        found = find(text, {"MY_SECRET": VALUE, "OTHER": DB_PW})
        self.assertGreater(len(found), len(PatternTests.SHAPES))
        blob = "\n".join(repr(f) + str(f) + repr([f]) for f in found)
        for v in values:
            # a fragment of the secret body, not just the whole token
            frag = v[8:20] if len(v) >= 20 else v
            self.assertNotIn(frag, blob, v[:10])
        self.assertNotIn(VALUE, blob)
        self.assertNotIn(DB_PW, blob)
        self.assertNotIn(base64.b64encode(VALUE.encode()).decode(), blob)

    def test_str_of_finding_names_rule_var_and_line(self):
        (f,) = find(f"\nx {VALUE}", {"MY_SECRET": VALUE})
        self.assertEqual(str(f), "own-secret:MY_SECRET at line 2")
        (g,) = find(AWS)
        self.assertEqual(str(g), "aws-key-id at line 1")

    def test_no_logging_of_values(self):
        with self.assertNoLogs("pps.secrets", level=logging.DEBUG):
            find(f"{ANT} {VALUE}", {"V": VALUE})
            redact(f"{ANT} {VALUE}", {"V": VALUE})

    def test_cap_warnings_never_contain_values(self):
        text = f"{VALUE} {ANT} " + "x" * 400
        with self.assertLogs("pps.secrets", level=logging.DEBUG) as cm:
            find(text, {"V": VALUE}, max_input=100)
            redact(text, {"V": VALUE}, max_input=100)
            find(text, {"V": VALUE}, max_seconds=-1)
        out = "\n".join(cm.output)
        for secret in (VALUE, ANT, ANT[10:20], VALUE[5:15]):
            self.assertNotIn(secret, out)


class RedactParityTests(unittest.TestCase):
    """slackcc's tests/test_sanitize_outbound.py scrub() cases, run against
    redact(): same text in, same text and labels out (own secrets arrive via
    ``known``, as slackcc passes them)."""

    def test_clean_text_returned_identical_with_no_findings(self):
        text = "Just a normal reply with no secrets in it at all."
        clean, findings = redact(text)
        self.assertEqual((clean, findings), (text, []))

    def test_private_key_block(self):
        text = ("here's the key:\n-----BEGIN RSA PRIVATE KEY-----\n"
                "MIIBogIBAAJBAK...redacted-body...\n-----END RSA PRIVATE KEY-----\nthanks")
        clean, findings = redact(text)
        self.assertNotIn("-----BEGIN", clean)
        self.assertNotIn("-----END", clean)
        self.assertIn("[redacted:private-key]", clean)
        self.assertEqual(findings, ["private-key"])

    def test_slack_tokens(self):
        for prefix in ("xoxb", "xoxa", "xoxp"):
            tok = f"{prefix}-1234567890-abcdefghij"
            clean, findings = redact(f"the token is {tok} ok")
            self.assertNotIn(tok, clean)
            self.assertIn("[redacted:slack-token]", clean)
            self.assertEqual(findings, ["slack-token"])

    def test_xapp_token(self):
        clean, findings = redact("socket mode token xapp-1-A012345-1234567890-abcdefghijklmnop in use")
        self.assertNotIn("xapp-1-A012345", clean)
        self.assertIn("[redacted:slack-app-token]", clean)
        self.assertEqual(findings, ["slack-app-token"])

    def test_aws_github_jwt_openai_anthropic(self):
        cases = [("aws key AKIAIOSFODNN7EXAMPLE was found", "AKIAIOSFODNN7EXAMPLE", "aws-key-id"),
                 (f"github token {'ghp_' + 'a' * 36} leaked", "ghp_" + "a" * 36, "github-token"),
                 (f"here is a jwt: {JWT_STRICT} thanks", JWT_STRICT, "jwt"),
                 (f"my openai key is {'sk-' + 'a' * 30} ok", "sk-" + "a" * 30, "openai-key"),
                 (f"my anthropic key is {'sk-ant-' + 'a' * 30} ok", "sk-ant-" + "a" * 30, "anthropic-key")]
        for text, tok, label in cases:
            clean, findings = redact(text)
            self.assertNotIn(tok, clean)
            self.assertIn(f"[redacted:{label}]", clean)
            self.assertEqual(findings, [label])

    def test_own_secret_exact_match_replaces_and_labels(self):
        token = "xoxb-own-secret-unique-marker-99887766"
        clean, findings = redact(f"posting with token {token} attached", {"SLACK_BOT_TOKEN": token})
        self.assertNotIn(token, clean)
        self.assertIn("[redacted:SLACK_BOT_TOKEN]", clean)
        self.assertIn("own-secret:SLACK_BOT_TOKEN", findings)

    def test_multiple_findings_accumulate(self):
        gh = "ghp_" + "b" * 36
        clean, findings = redact(f"aws {AWS} and github {gh} both leaked")
        self.assertNotIn(AWS, clean)
        self.assertNotIn(gh, clean)
        self.assertEqual(set(findings), {"aws-key-id", "github-token"})
        self.assertEqual(len(findings), 2)

    def test_idempotent_on_already_redacted_text(self):
        text = f"aws {AWS} github {'ghp_' + 'c' * 36} api_key=\"abcdefghijklmnopqrstuvwxyz\" {PEM} {SLACK_HOOK}"
        once, found_once = redact(text)
        twice, found_twice = redact(once)
        self.assertEqual(once, twice)
        self.assertEqual(found_twice, [])
        self.assertGreater(len(found_once), 0)

    def test_own_secret_idempotent_when_value_is_gone(self):
        token = "xapp-idempotent-check-1234567890"
        once, f1 = redact(f"t3 token {token} in use", {"SLACKCC_T3_TOKEN": token})
        twice, f2 = redact(once)
        self.assertEqual(once, twice)
        self.assertEqual(f1, ["own-secret:SLACKCC_T3_TOKEN"])
        self.assertEqual(f2, [])

    def test_redacting_then_finding_finds_nothing(self):
        text = "\n".join(t for _, t in PatternTests.SHAPES) + f"\nDATABASE_URL=postgres://a:{DB_PW}@h/d\npassword={VALUE}\n{VALUE}"
        clean, _ = redact(text, {"V": VALUE})
        self.assertEqual(find(clean, {"V": VALUE}), [])


class CapTests(unittest.TestCase):
    def test_defaults_are_documented_constants(self):
        self.assertEqual(secrets.DEFAULT_MAX_INPUT, 1 << 20)
        self.assertGreater(secrets.DEFAULT_MAX_SECONDS, 0)

    def test_find_reports_the_unscanned_tail(self):
        text = "a" * 100 + " " + AWS + " " + "b" * 100          # token at 101..121
        got = find(text, max_input=150)
        self.assertEqual([f.label for f in got], ["aws-key-id", "input-truncated"])
        self.assertEqual((got[-1].start, got[-1].end), (150, len(text)))

    def test_find_under_the_cap_is_unaffected_and_larger_caps_work(self):
        text = "a" * 100 + " " + AWS
        self.assertEqual(labels(text, max_input=len(text)), ["aws-key-id"])
        # past the default cap, an explicit larger cap scans everything
        big = "z" * (secrets.DEFAULT_MAX_INPUT + 10) + " " + AWS
        self.assertEqual(labels(big), ["input-truncated"])
        self.assertEqual(labels(big, max_input=len(big)), ["aws-key-id"])

    def test_truncated_finding_line_counts_newlines(self):
        got = find("a\nb\nc\nd\ne\n", max_input=6)
        self.assertEqual((got[-1].label, got[-1].line), ("input-truncated", 4))

    def test_redact_drops_the_unscanned_tail_and_says_so(self):
        text = "head " + AWS + " " + "x" * 2000 + " " + ANT
        clean, got = redact(text, max_input=1000)
        self.assertNotIn(AWS, clean)
        self.assertNotIn(ANT, clean)
        self.assertTrue(clean.startswith("head [redacted:aws-key-id] "))
        self.assertTrue(clean.endswith("[redacted:input-truncated]"))
        self.assertEqual(got, ["aws-key-id", "input-truncated"])

    def test_token_straddling_the_cut_does_not_leak_a_prefix(self):
        for cut in range(300, 340):
            text = "x" * 320 + ANT + "y" * 50
            clean, got = redact(text, max_input=cut)
            self.assertNotIn("sk-ant", clean, cut)
            self.assertIn("input-truncated", got)

    def test_redact_truncation_with_a_match_straddling_the_drop_point(self):
        pem = "-----BEGIN PRIVATE " "KEY-----\n" + "A" * 400 + "\n-----END PRIVATE " "KEY-----"
        clean, _ = redact("x" * 100 + pem + "y" * 100, max_input=500)
        self.assertNotIn("AAAA", clean)
        self.assertNotIn("BEGIN", clean)

    def test_redact_with_larger_cap_returns_everything(self):
        text = "q" * (secrets.DEFAULT_MAX_INPUT + 5) + " " + AWS
        clean, got = redact(text, max_input=len(text))
        self.assertEqual(got, ["aws-key-id"])
        self.assertTrue(clean.endswith("[redacted:aws-key-id]"))

    def test_bytes_cap(self):
        got = find(b"a" * 50 + AWS.encode() + b"b" * 50, max_input=60)
        self.assertEqual([f.label for f in got], ["input-truncated"])

    def test_timeout_is_fail_closed(self):
        text = f"hello {ANT}"
        got = find(text, max_seconds=-1)
        self.assertEqual([f.label for f in got], ["scan-timeout"])
        clean, labs = redact(text, max_seconds=-1)
        self.assertEqual((clean, labs), ("[redacted:scan-timeout]", ["scan-timeout"]))
        clean, labs = redact(text.encode(), max_seconds=-1)
        self.assertEqual(clean, b"[redacted:scan-timeout]")
        # known-values phase also respects the budget
        self.assertEqual(labels("abc", {"V": VALUE}, max_seconds=-1), ["scan-timeout"])

    def test_empty_input(self):
        self.assertEqual(find(""), [])
        self.assertEqual(redact(""), ("", []))
        self.assertEqual(find(b""), [])


class PerformanceTests(unittest.TestCase):
    """Adversarial 1 MiB inputs must scan in (roughly) linear time. The bound
    is generous (a laptop does each in well under a second) -- it only has to
    separate linear from quadratic."""

    def test_pathological_inputs_stay_bounded(self):
        n = secrets.DEFAULT_MAX_INPUT
        cases = {
            "one long run": "a" * n,
            "newlines": "\n" * n,
            "whitespace": " " * n,
            "repeated password": "password" * (n // 8),
            "password then spaces": "password  " * (n // 10),
            "repeated begin": "-----BEGIN PRIVATE KEY-----" * (n // 27),
            "repeated sk-": "sk-" * (n // 3),
            "repeated eyJ": "eyJ" * (n // 3),
            "eyJ run": "eyJ" + "a" * n,
            "eyJ dots": "eyJ." * (n // 4),
            "repeated xoxb-": "xoxb-" * (n // 5),
            "unterminated quotes": 'token="' * (n // 7),
            "token run": "token" * (n // 5) + "=",
            "export lines": "export token\n" * (n // 13),
            "repeated db scheme": "postgres://:" * (n // 12),
            "long db password": "postgres://a:" + "b" * n,
            "repeated api_key=": "api_key=" * (n // 8),
        }
        for name, text in cases.items():
            with self.subTest(case=name):
                t0 = time.monotonic()
                find(text[:n])
                redact(text[:n])
                self.assertLess(time.monotonic() - t0, 8.0, name)

    def test_many_known_values(self):
        known = {f"VAR_{i}": f"secret-value-number-{i:04d}" for i in range(50)}
        text = ("filler text " * 5000) + known["VAR_7"]
        t0 = time.monotonic()
        self.assertEqual([f.var for f in find(text, known)], ["VAR_7"])
        self.assertLess(time.monotonic() - t0, 5.0)


class ImportIsolationTests(unittest.TestCase):
    def test_secrets_imports_only_the_stdlib(self):
        src = os.path.join(os.path.dirname(__file__), "..", "src")
        code = (
            "import sys\n"
            f"sys.path.insert(0, {src!r})\n"
            "before = set(sys.modules)\n"
            "import pps.secrets\n"
            "new = {m.split('.')[0] for m in set(sys.modules) - before}\n"
            "bad = sorted(m for m in new if m not in sys.stdlib_module_names and m not in ('pps', '_'))\n"
            "assert not bad, bad\n"
            "assert 'pps.server' not in sys.modules and 'pps.judge' not in sys.modules\n"
            "print('ok')\n"
        )
        r = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True)
        self.assertEqual(r.stdout.strip(), "ok", r.stderr)


if __name__ == "__main__":
    unittest.main()
