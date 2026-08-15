"""Pure dedicated-server authentication page rendering."""
from __future__ import annotations

import html


def render_login(token: str, message: str = "", error: bool = False) -> bytes:
    note = ""
    if message:
        cls = "error" if error else "note"
        note = f'<p class="{cls}">{html.escape(message)}</p>'
    body = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Onion Sentinel sign in</title><style>
body{{margin:0;background:#07131d;color:#edf7ff;font:16px system-ui;display:grid;place-items:center;min-height:100vh}}
main{{width:min(420px,calc(100% - 32px));border:1px solid #16485a;padding:24px;background:#0b1823}}
label{{display:block;color:#a9bbcf;margin:16px 0 8px}}input,button{{box-sizing:border-box;width:100%;min-height:44px;font:inherit}}
input{{background:#07131d;color:#edf7ff;border:1px solid #315064;padding:10px}}button{{margin-top:16px;background:#16bfd5;color:#041016;border:0;font-weight:700}}
.error{{color:#ff7188}}.note{{color:#71e6f4}}a{{color:#71e6f4}}</style></head>
<body><main><h1>Onion Sentinel</h1><p>Secure sign in</p>{note}
<form method="post" action="/admin/login"><input type="hidden" name="token" value="{html.escape(token)}">
<label for="username">Username</label><input id="username" name="username" type="text" autocomplete="username" maxlength="64">
<label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required autofocus>
<button type="submit">Sign in</button></form><p><a href="/settings.html">Return to Settings</a></p></main></body></html>"""
    return body.encode("utf-8")


def render_admin_status(token: str) -> bytes:
    body = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Onion Sentinel Administration</title></head><body><h1>Onion Sentinel Administration</h1>
<p>Authenticated. Administration access is enabled for this browser session.</p>
<p><a href="/settings.html">Open Settings</a></p><form method="post" action="/admin/logout">
<input type="hidden" name="token" value="TOKEN"><button type="submit">Sign out</button></form>
<script>
function adminCsrf(){const prefix='onion_sentinel_csrf=';for(const part of document.cookie.split(';')){const value=part.trim();if(value.startsWith(prefix)){try{return decodeURIComponent(value.slice(prefix.length))}catch(_){return ''}}}return ''}
document.querySelector('form[action="/admin/logout"]').addEventListener('submit',async(event)=>{event.preventDefault();const csrf=adminCsrf();if(!csrf){window.location='/admin/login';return}const response=await fetch('/admin/logout',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','X-Onion-Sentinel-CSRF':csrf},credentials:'same-origin',body:new URLSearchParams(new FormData(event.currentTarget)).toString()});window.location=response.ok?'/admin/login':'/admin'});
</script></body></html>"""
    return body.replace("TOKEN", html.escape(token)).encode("utf-8")


def render_session_status(token: str, role: object) -> bytes:
    safe_role = html.escape(str(role or "viewer").title())
    body = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Onion Sentinel session</title></head><body><h1>Onion Sentinel session</h1>
<p>Authenticated as <strong>ROLE</strong>.</p>
<p><a href="/">Open dashboard</a></p><form method="post" action="/admin/logout">
<input type="hidden" name="token" value="TOKEN"><button type="submit">Sign out</button></form>
<script>
function sessionCsrf(){const prefix='onion_sentinel_csrf=';for(const part of document.cookie.split(';')){const value=part.trim();if(value.startsWith(prefix)){try{return decodeURIComponent(value.slice(prefix.length))}catch(_){return ''}}}return ''}
document.querySelector('form[action="/admin/logout"]').addEventListener('submit',async(event)=>{event.preventDefault();const csrf=sessionCsrf();if(!csrf){window.location='/admin/login';return}const response=await fetch('/admin/logout',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','X-Onion-Sentinel-CSRF':csrf},credentials:'same-origin',body:new URLSearchParams(new FormData(event.currentTarget)).toString()});window.location=response.ok?'/admin/login':'/session'});
</script></body></html>"""
    return (
        body.replace("TOKEN", html.escape(token))
        .replace("ROLE", safe_role)
        .encode("utf-8")
    )


__all__ = ("render_admin_status", "render_login", "render_session_status")
