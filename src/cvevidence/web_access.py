"""Fail-closed identity policy for the separate hosted entry point."""
import hashlib
import re

def principal(user, allowed_emails):
    email = user.get("email", "")
    subject = user.get("sub", "")
    if (not user.get("is_logged_in") or user.get("email_verified") is not True
            or not isinstance(email, str) or not isinstance(subject, str) or not subject):
        raise ValueError("Verified Google identity required")
    if email.casefold() not in {e.strip().casefold() for e in allowed_emails if isinstance(e, str)}:
        raise ValueError("Account is not allowed")
    return hashlib.sha256(("google:" + subject).encode()).hexdigest()

def release_label(value):
    return value if re.fullmatch(r"[a-f0-9]{7,40}", value or "") else "unversioned"
