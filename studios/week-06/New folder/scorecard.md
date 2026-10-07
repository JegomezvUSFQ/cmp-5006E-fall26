### Task 3: Control Scorecard & Responsible Disclosure

**Finding:** Reflected XSS at `GET /?name=`
**Control Evaluated:** Output Encoding via `html.escape()` (as implemented in `/safe`)

| Axis | Name | Evaluation |
|:---:|---|---|
| **1** | **Threat Model** | Unauthenticated remote attacker (no credentials required) who tricks a legitimate victim into clicking a maliciously crafted link. |
| **2** | **Guarantee** | Guarantees that dangerous characters (`<`, `>`, `&`) are safely rendered as harmless text, **provided that** the input is reflected within a standard HTML text context (e.g., inside an `<h1>` tag) and not inside a `<script>` block or an unquoted HTML attribute. |
| **3** | **Coverage** | 1/1 (100%) of tested tag-injection payloads (e.g., `<script>alert('XSS-FIRED')</script>`) were blocked. The payload was successfully HTML-encoded to `&lt;script&gt;`. |
| **4** | **Bypass** | **Attempt documented:** Attempted a context breakout using double quotes and event handlers (e.g., `" onmouseover="alert(1)`). **Result:** Failed. Because this specific endpoint reflects the input as plain text rather than inside an HTML attribute, the bypass did not execute. Note: If the app placed this input inside a JavaScript block (e.g., `var name = "INPUT";`), standard `html.escape()` would be insufficient and a bypass would be trivial. |

---

### Responsible Disclosure Note

> **Vulnerability Report: Reflected XSS in `vuln-web`**
> A Reflected Cross-Site Scripting (XSS) vulnerability exists in the `GET /?name=` endpoint, allowing an unauthenticated attacker to execute arbitrary JavaScript in the victim's browser, potentially leading to session hijacking. 
> **Fix:** Sanitize the untrusted user input before rendering the HTML response by using output encoding (e.g., `html.escape(name)`), exactly as it is currently implemented in the `/safe` endpoint.