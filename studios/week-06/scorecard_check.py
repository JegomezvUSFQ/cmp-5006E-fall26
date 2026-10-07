"""Repeatable local check for the XSS scorecard's coverage and bypass attempt."""

from html.parser import HTMLParser

from webharness import reflect_safe_send, reflect_send


PAYLOADS = [
    "<script>alert(1)</script>",
    "<ScRiPt>alert(2)</ScRiPt>",
    "<script type='text/javascript'>alert(3)</script>",
    "<script defer>alert(4)</script>",
    "<script\n>alert(5)</script>",
    "</h1><script>alert(6)</script>",
    "<svg onload=alert(7)>",
    "<img src=x onerror=alert(8)>",
    "<body onload=alert(9)>",
    "<input autofocus onfocus=alert(10)>",
    "<details open ontoggle=alert(11)>",
    "<iframe onload=alert(12)>",
    "<video src=x onerror=alert(13)>",
    "<audio src=x onerror=alert(14)>",
    "<marquee onstart=alert(15)>",
    "<button onclick=alert(16)>click</button>",
    "<a href='javascript:alert(17)'>click</a>",
    "<iframe srcdoc='<script>alert(18)</script>'>",
    "<math onmouseover=alert(19)>",
    "<div onpointerenter=alert(20)>hover</div>",
]


class ActiveMarkup(HTMLParser):
    def __init__(self):
        super().__init__()
        self.found = False

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        self.found |= (tag == "script"
                       or any(name.startswith("on") for name in values)
                       or (values.get("href") or "").lower().startswith("javascript:")
                       or "srcdoc" in values)


def has_active_markup(body: str) -> bool:
    parser = ActiveMarkup()
    parser.feed(body)
    return parser.found


def main():
    assert len(PAYLOADS) == len(set(PAYLOADS)) == 20
    baseline = [has_active_markup(reflect_send(p)) for p in PAYLOADS]
    protected = [has_active_markup(reflect_safe_send(p)) for p in PAYLOADS]
    assert all(baseline), "An attack did not produce active markup at the vulnerable endpoint"
    assert not any(protected), "An attack produced active markup at the safe endpoint"

    bypass = "</h1><img src=x onerror=alert(21)>"
    bypass_baseline = has_active_markup(reflect_send(bypass))
    bypass_safe = has_active_markup(reflect_safe_send(bypass))
    assert bypass_baseline and not bypass_safe

    print(f"attacks: {sum(baseline)}/20 active at /; {sum(protected)}/20 active at /safe")
    print(f"control coverage: {20 - sum(protected)}/20 blocked at /safe")
    print(f"bypass attempt: active at /={bypass_baseline}; active at /safe={bypass_safe}")


if __name__ == "__main__":
    main()
