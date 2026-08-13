"""
broken_access.py — Planted Broken Access Control vulnerability fixture.

Planted issues (3 variants):
  Line 24 — /admin/delete route with no @login_required or auth check  [HIGH]
  Line 33 — /admin/users route exposed without any auth guard           [HIGH]
  Line 44 — /api/user/<id> returns any user's data without ownership check [HIGH]
"""

from flask import Flask, request, jsonify, session

app = Flask(__name__)
app.secret_key = "dev-secret"  # separate issue but note it's hardcoded


def get_db():
    import sqlite3
    return sqlite3.connect("app.db")


# ── Planted Issue #1: Admin delete route with no auth check ───────────────
@app.route("/admin/delete", methods=["POST"])       # line 22
def admin_delete():
    # VULNERABILITY: No authentication check — any unauthenticated user can call this
    record_id = request.json.get("id")              # line 24
    db = get_db()
    db.execute("DELETE FROM records WHERE id = ?", (record_id,))
    db.commit()
    return jsonify({"status": "deleted"})


# ── Planted Issue #2: Admin user listing — no login required ──────────────
@app.route("/admin/users", methods=["GET"])         # line 33
def list_all_users():
    # VULNERABILITY: No auth guard — any visitor can enumerate all users
    db = get_db()
    users = db.execute("SELECT id, username, email FROM users").fetchall()
    return jsonify(users)


# ── Planted Issue #3: User profile route — no ownership check ─────────────
@app.route("/api/user/<int:user_id>", methods=["GET"])  # line 44
def get_user_profile(user_id: int):
    # VULNERABILITY: Returns any user's profile without verifying
    # the requester is that user or an admin (IDOR — Insecure Direct Object Reference)
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return jsonify(user)


# ── Clean reference — route with proper auth guard (should NOT flag) ────────
def login_required(f):
    """Simple auth decorator checking session."""
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


@app.route("/profile", methods=["GET"])
@login_required
def my_profile():
    user_id = session["user_id"]
    db = get_db()
    return jsonify(db.execute("SELECT id, username FROM users WHERE id = ?", (user_id,)).fetchone())
