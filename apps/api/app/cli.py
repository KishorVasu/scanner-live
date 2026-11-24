"""Bootstrap: `python -m app.cli create-admin --email you@example.com` (password read from the terminal)."""

import argparse
import asyncio
import getpass
import sys

from sqlalchemy import select

from app.core.security import MIN_PASSWORD_LENGTH, hash_password
from app.db.models import ActorType, Role, User
from app.db.session import get_sessionmaker
from app.modules.audit.service import record


async def create_admin(email: str, password: str) -> None:
    async with get_sessionmaker()() as db:
        email = email.strip().lower()
        if await db.scalar(select(User.id).where(User.email == email)):
            sys.exit("user exists")
        role = await db.scalar(select(Role).where(Role.name == "admin"))
        user = User(email=email, password_hash=hash_password(password), roles=[role])
        db.add(user)
        await db.flush()
        record(db, actor_type=ActorType.system, actor_id="cli", action="users.create_admin", outcome="success",
               target_type="user", target_id=user.id)
        await db.commit()
    print(f"created admin {email}; TOTP enrolment happens at first login")


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("create-admin")
    p.add_argument("--email", required=True)
    args = parser.parse_args()
    password = getpass.getpass("Password: ")
    if len(password) < MIN_PASSWORD_LENGTH or password != getpass.getpass("Repeat: "):
        sys.exit(f"passwords must match and be at least {MIN_PASSWORD_LENGTH} characters")
    asyncio.run(create_admin(args.email, password))


if __name__ == "__main__":
    main()
