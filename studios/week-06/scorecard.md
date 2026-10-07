# Week 6 Studio — Injection Findings and Control Scorecard

Date: 2026-10-01. Target: the course's `labs/vuln-web` app on `127.0.0.1`.

## Task 1 — Oracle-confirmed findings

| Sink | Confirmation | Control | Reliability |
|---|---|---|---|
| `POST /login` — SQL injection | 3/3 username payloads returned the synthetic admin canary; the oracle searched for the canary, not a changed login message. | Real user with wrong password: 0/3. | Each attack 3/3; deterministic in these trials. |
| `GET /?name=` — reflected XSS | An unescaped `<script>` element containing the test marker appeared in the HTML: 3/3. | The same payload at `/safe`: 0/3. | 3/3 versus 0/3; deterministic in these trials. |
| `POST /ping` — command injection | The parsed JSON field `injection_detected` was `true` for both metacharacter payloads: 3/3 each. | Plain host: 0/3. | Each attack 3/3; deterministic in these trials. |

The XSS oracle checks an unescaped script element in the known HTML text context. No browser execution was measured. The command endpoint simulates a shell and does not execute a command.

## Task 2 — Same-source duel

Both arms read `labs/vuln-web/app/vulnweb_app.py` and were scored against `studios/week-06/ground_truth.json` (the local fixture supplied with this checkout).

| Arm | True positives | False positives | Missed | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| Line-oriented regex scanner | 2 | 0 | 1 | 100% | 67% | 0.80 |
| Parsed, canned LLM review | 3 | 2 | 0 | 60% | 100% | 0.75 |

The scanner missed SQL injection in `do_login` because the query spans two lines. The canned LLM review correctly named all three intentional sinks, but falsely claimed Broken Access Control in `do_login` and XSS in the encoded `do_reflect_safe` endpoint. The app has no session or role logic to support the access-control claim. Neither arm truthfully found a Broken Access Control vulnerability. This measures a supplied review string, not a live model or its repeatability.

## Task 3 — Control Scorecard: `html.escape` at `/safe`

| Axis | Before | After control | Evidence |
|---|---|---|---|
| 1. Threat model | An unauthenticated attacker can choose the `name` query value at `/`. | The attacker has the same capability at `/safe`; no credentials or network position are needed beyond local access to this lab. | The two handlers in `vulnweb_app.py` and local requests in `scorecard_check.py`. |
| 2. Guarantee | Raw input is inserted into an HTML text node; attacker markup can become elements. | If **every untrusted value is escaped for this HTML text context before interpolation**, `<`, `>`, `&`, and quotes cannot create attacker-controlled tags or attributes. This guarantee does not cover values later placed in JavaScript, CSS, URLs, or unquoted attributes. | `do_reflect_safe` calls `html.escape(name)` before interpolation. |
| 3. Coverage | 0/20 sampled payloads blocked: all 20 produced active markup at `/`. | 20/20 sampled payloads blocked: 0 produced active markup at `/safe`. | `py scorecard_check.py` on 2026-10-01; the script includes 20 distinct script, event-handler, `javascript:` and `srcdoc` inputs, parsed as HTML. |
| 4. Bypass | `</h1><img src=x onerror=alert(21)>` produced an event-handler element at `/`. | The same attempted bypass produced no active markup at `/safe`; no working bypass was found for this text context. | `scorecard_check.py` prints `active at /=True; active at /safe=False`. |

### Where we may have been unfair, and what we did not test

The 20 inputs are a chosen local sample, not an exhaustive XSS corpus. The `HTMLParser` check detects potentially active markup; it does not prove browser execution, and some event handlers require interaction. There was one explicit bypass attempt. We did not test browser quirks, DOM rewriting by later JavaScript, or other output contexts. The source scanner is a small supplied regex implementation and the LLM arm is supplied text, so this is not a measurement of Semgrep, CodeQL, or a live LLM.

### Responsible disclosure note (practice; not sent)

`GET /?name=` reflects unescaped user input into HTML, permitting a script element in the response and potential script execution for a visitor.
Please encode the `name` value for its HTML text context as `/safe` does, then add a regression check for raw script and event-handler markup.

## Reproduce locally

From `studios/week-06`, run `py test_studio.py`, `py starter.py`, and `py scorecard_check.py`. The harness starts the target in-process on `127.0.0.1` and needs no Docker or live model.
