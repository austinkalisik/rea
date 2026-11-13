"""Build an offline prototype from the observable browser interface."""

from html import escape
from urllib.parse import urljoin, urlsplit

DOM_MAP = """() => {
  const visible = element => element.getClientRects().length &&
    getComputedStyle(element).visibility === 'visible';
  const label = element => (element.labels?.[0]?.innerText ||
    element.getAttribute('aria-label') || element.getAttribute('placeholder') ||
    element.innerText || element.getAttribute('name') || '').trim().slice(0, 160);
  const select = (selector, limit) =>
    [...document.querySelectorAll(selector)].filter(visible).slice(0, limit);
  return {
    headings: select('h1,h2,h3,[role=heading]', 24).map(element => ({
      level: element.tagName.toLowerCase(), text: label(element)
    })),
    links: select('a[href]', 36).map(element => ({
      label: label(element), href: element.getAttribute('href')
    })),
    forms: select('form', 8).map(form => ({
      method: (form.getAttribute('method') || 'get').toUpperCase(),
      action: form.getAttribute('action') || '',
      controls: [...form.querySelectorAll('input,select,textarea,button')]
        .filter(visible).slice(0, 20).map(element => ({
          label: label(element), type: element.type || element.tagName.toLowerCase(),
          name: element.getAttribute('name') || '', required: !!element.required
        }))
    })),
    buttons: select('button,[role=button]', 24).map(element => ({
      label: label(element), type: element.type || 'button'
    }))
  };
}"""


def public_route(base, reference):
    """Keep the observed host and path while dropping credentials and query values."""
    url = urlsplit(urljoin(base, reference))
    if url.scheme not in ("http", "https") or not url.hostname:
        return ""
    return url.hostname + (url.path or "/")


def reconstruct(output, url, title, interface, requests):
    for link in interface["links"]:
        link["href"] = public_route(url, link["href"])
    for form in interface["forms"]:
        form["action"] = public_route(url, form["action"])

    login_visible = any(
        control["type"] == "password"
        for form in interface["forms"] for control in form["controls"]
    )
    workflows = [
        {"observation": "A password form is visible",
         "likelyPurpose": "Sign-in",
         "verification": "Observed controls only. No form submission or authenticated view."}
    ] if login_visible else []
    data = {
        "page": title,
        "interface": interface,
        "workflows": workflows,
        "observedDataRequests": requests,
        "coverage": "One anonymous page render. Form actions are declared destinations. "
                    "Observed requests are limited to browser fetch and XHR requests during the capture.",
        "unobserved": "Authenticated screens, backend source, database schema, and business rules."
    }

    parts = [
        '<!doctype html><html lang="en"><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; form-action \'none\'; base-uri \'none\'">',
        '<title>Offline REA prototype</title>',
        '<style>body{background:#0b1220;color:#eef4ff;font:16px system-ui;margin:0;padding:32px}'
        'main{max-width:720px;margin:auto}section{border:1px solid #334155;border-radius:14px;padding:20px;margin:16px 0}'
        'label{display:block;margin:14px 0}input,button{display:block;padding:10px;margin-top:6px;border-radius:7px}'
        'small,p{color:#aabbd2}</style><main>',
        '<small>REA OFFLINE PROTOTYPE</small>',
        '<h1>' + escape(title or 'Captured public page') + '</h1>',
        '<p>Interface sketch from visible controls and headings. All controls are disabled.</p>'
    ]
    for heading in interface["headings"]:
        if heading["text"] and heading["text"] != title:
            parts.append('<h2>' + escape(heading["text"]) + '</h2>')
    for form in interface["forms"]:
        parts.append('<section><h2>Form</h2><small>' + escape(form["method"] + ' ' + form["action"]) + '</small>')
        for control in form["controls"]:
            name = escape(control["label"] or control["name"] or control["type"])
            if control["type"] in ("button", "submit", "reset"):
                parts.append('<button disabled>' + name + '</button>')
            else:
                kind = control["type"] if control["type"] in ("password", "email", "checkbox", "radio", "number") else "text"
                parts.append('<label>' + name + '<input disabled type="' + kind + '"></label>')
        parts.append('</section>')
    if interface["links"]:
        parts.append('<section><h2>Visible navigation</h2><ul>')
        for link in interface["links"]:
            parts.append('<li>' + escape(link["label"] or link["href"]) + '</li>')
        parts.append('</ul></section>')
    if interface["buttons"]:
        parts.append('<section><h2>Visible actions</h2>')
        for button in interface["buttons"]:
            parts.append('<button disabled>' + escape(button["label"] or button["type"]) + '</button>')
        parts.append('</section>')
    parts.append('</main></html>')
    (output / "frontend-prototype.html").write_text("\n".join(parts), encoding="utf-8")
    return data
