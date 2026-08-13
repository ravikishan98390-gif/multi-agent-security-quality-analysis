"""
xss_python.py — Planted Cross-Site Scripting (XSS) vulnerability fixture.

Planted issues (3 variants):
  Line 22 — render_template_string() with user-controlled input               [HIGH]
  Line 32 — Flask Markup() wrapping unsanitised user data                     [HIGH]
  Line 42 — Jinja2 template string with |safe filter on user content          [HIGH]
"""

from flask import Flask, request, render_template_string
from markupsafe import Markup

app = Flask(__name__)


# ── Planted Issue #1: render_template_string with user input ───────────────
@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    # VULNERABILITY: user-controlled `name` is rendered as a Jinja2 template
    # An attacker can pass "{{7*7}}" to execute expressions, or inject scripts
    template = "<h1>Hello, " + name + "!</h1>"
    return render_template_string(template)          # line 22


# ── Planted Issue #2: Flask Markup() on unescaped user input ──────────────
@app.route("/display")
def display():
    user_comment = request.form.get("comment", "")
    # VULNERABILITY: Markup() marks content as safe, bypassing auto-escaping
    safe_comment = Markup(user_comment)              # line 32
    return f"<div>{safe_comment}</div>"


# ── Planted Issue #3: Jinja2 |safe on user-controlled variable ─────────────
@app.route("/render")
def render_profile():
    bio = request.args.get("bio", "")
    # VULNERABILITY: |safe filter disables HTML escaping for attacker-supplied bio
    template = "{% set user_bio = '" + bio + "' %}<p>{{ user_bio | safe }}</p>"  # line 42
    return render_template_string(template)


# ── Clean reference — properly escaped output (should NOT be flagged) ───────
@app.route("/safe_greet")
def safe_greet():
    from markupsafe import escape
    name = request.args.get("name", "")
    return f"<h1>Hello, {escape(name)}!</h1>"
