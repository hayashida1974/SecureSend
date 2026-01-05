# filters.py
from datetime import datetime

def format_datetime(value):
    if not value:
        return ""
    try:
        return datetime.fromisoformat(value).strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return value

def format_filesize(value):
    if value is None:
        return ""
    try:
        size = float(value)
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"
    except (ValueError, TypeError):
        return value

def format_mask_email(email, head=3, tail=2):
    if not email or "@" not in email:
        return email

    local, domain = email.split("@", 1)

    if len(local) <= head + tail:
        masked_local = "*" * len(local)
    else:
        masked_local = (
            local[:head]
            + "*" * (len(local) - head - tail)
            + local[-tail:]
        )

    return f"{masked_local}@{domain}"
