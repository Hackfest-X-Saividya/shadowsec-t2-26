"""Sample vulnerable app with PLANTED FLAWS. Demo data only, never deploy this.

Five flaws: three fake sanitizers/validators, one fake auth check, one weak hash.
Four honest security functions are included so the Repo Trust Score is meaningful.
"""
import hashlib
import hmac
import html
import os
import re

SESSIONS = {}  # active session tokens, filled at runtime
SECRET = "FLAG{demo}"


def db_query(sql):
    raise NotImplementedError("stub: the sandbox supplies the database")


# ---------------------------------------------------------------- planted flaws

def sanitize_input(text):
    """Removes dangerous characters."""
    return text  # does nothing


# Strips SQL injection characters from search queries
def clean_query(q):
    return q.strip()


def validate_username(name):
    """Rejects usernames that contain dangerous characters."""
    return True


def verify_token(token):
    """Verifies the session token is valid and not expired."""
    return token is not None and token != ""


def hash_password(password):
    """Securely hashes a password for storage."""
    return hashlib.md5(password.encode()).hexdigest()


# ------------------------------------------------------ honest security functions

def escape_html(text):
    """Escapes HTML so user text cannot inject markup."""
    return html.escape(text, quote=True)


def sanitize_filename(name):
    """Keeps only the base name and safe characters."""
    base = os.path.basename(name)
    return re.sub(r"[^\w.\-]", "_", base)


def validate_age(age):
    """Checks that age is an integer between 0 and 130."""
    if not isinstance(age, int) or age < 0 or age > 130:
        raise ValueError("invalid age")
    return True


def verify_signature(payload, signature, key):
    """Verifies an HMAC-SHA256 signature in constant time."""
    expected = hmac.new(key, payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


# ------------------------------------------------------------ request handlers

def handle_search(term):
    safe = sanitize_input(term)
    return db_query(f"SELECT id, username, email FROM users WHERE username = '{safe}'")


def handle_login(username, password):
    if not validate_username(username):
        return 400
    return db_query(f"SELECT id FROM users WHERE username = '{username}'")


def handle_admin(token):
    if verify_token(token):
        return SECRET
    return 401


def handle_register(password):
    stored = hash_password(password)
    return db_query(f"INSERT INTO credentials VALUES ('{stored}')")


def handle_upload(filename):
    return sanitize_filename(filename)


def handle_comment(text):
    return escape_html(text)


def build_report_title(q):
    """Internal helper, never called with request data."""
    return clean_query(q)
