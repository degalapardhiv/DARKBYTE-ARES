#!/usr/bin/env python3
"""Create an initial DARKBYTE ARES administrator without storing a password.

Usage:
    .venv/bin/python scripts/create_admin.py --email admin@example.com

The password is read from the ARES_ADMIN_PASSWORD environment variable or an
interactive prompt. It is never accepted as a command-line argument, logged or
written to disk in plaintext.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from email_validator import EmailNotValidError, validate_email  # noqa: E402
from sqlalchemy import select  # noqa: E402

from backend.core.config import get_settings  # noqa: E402
from backend.core.security import hash_password  # noqa: E402
from backend.database.session import (  # noqa: E402
    async_session_factory,
    close_db,
    init_db,
)
from backend.models.models import User  # noqa: E402
from backend.schemas.schemas import PASSWORD_POLICY  # noqa: E402

PASSWORD_ENV = "ARES_ADMIN_PASSWORD"


def _password_from_environment() -> str | None:
    value = os.environ.get(PASSWORD_ENV, "")
    return value or None


def _prompt_password() -> str:
    first = getpass.getpass("Administrator password: ")
    second = getpass.getpass("Confirm password: ")
    if first != second:
        raise ValueError("Passwords do not match.")
    return first


def _validate_password(password: str) -> None:
    if not PASSWORD_POLICY.match(password):
        raise ValueError(
            "Password must be 12+ characters and include uppercase, lowercase, "
            "a number and a symbol."
        )


async def create_admin(email: str, name: str, password: str) -> int:
    try:
        normalized = validate_email(email, check_deliverability=False).normalized
    except EmailNotValidError as exc:
        print(f"Invalid email address: {exc}", file=sys.stderr)
        return 2
    try:
        _validate_password(password)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    settings = get_settings()
    await init_db()
    try:
        async with async_session_factory() as db:
            existing = (
                await db.execute(select(User).where(User.email == normalized))
            ).scalar_one_or_none()
            if existing:
                print(
                    f"An account already exists for {normalized}; no changes made.",
                    file=sys.stderr,
                )
                return 1
            db.add(
                User(
                    email=normalized,
                    name=name.strip()[:120],
                    password_hash=hash_password(password),
                    role="admin",
                    is_active=True,
                    is_demo=False,
                    preferences={"notifications": True, "compactMode": False},
                )
            )
            await db.commit()
    finally:
        await close_db()

    print(f"Administrator created: {normalized}")
    print(f"Environment: {settings.app_env}")
    print("Store the password in a password manager and enable TLS before use.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a DARKBYTE ARES administrator.")
    parser.add_argument("--email", required=True, help="Administrator email address")
    parser.add_argument(
        "--name",
        default="ARES Administrator",
        help="Display name (default: ARES Administrator)",
    )
    args = parser.parse_args()

    password = _password_from_environment()
    if password is None:
        if not sys.stdin.isatty():
            print(
                f"Set {PASSWORD_ENV} or run this command from an interactive terminal.",
                file=sys.stderr,
            )
            return 2
        try:
            password = _prompt_password()
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled.", file=sys.stderr)
            return 130
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2

    return asyncio.run(create_admin(args.email, args.name, password))


if __name__ == "__main__":
    raise SystemExit(main())
