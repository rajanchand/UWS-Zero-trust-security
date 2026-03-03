"""Seed script - inserts default demo users with bcrypt hashed passwords.
Run:  python seed.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from app.config import settings
from app.database import get_supabase
from app.security import hash_password


USERS = [
    {"username": "superadmin", "email": "superadmin@zts.local", "role": "SuperAdmin", "password": "Password1!"},
    {"username": "hr_user", "email": "hr@zts.local", "role": "HR", "password": "Password1!"},
    {"username": "finance_user", "email": "finance@zts.local", "role": "Finance", "password": "Password1!"},
    {"username": "it_user", "email": "it@zts.local", "role": "IT", "password": "Password1!"},
    {"username": "cs_user", "email": "cs@zts.local", "role": "CustomerSupport", "password": "Password1!"},
]


def seed():
    db = get_supabase()

    for u in USERS:
        pw_hash = hash_password(u["password"])
        # skip if already exists
        existing = db.table("users").select("id").eq("username", u["username"]).execute()
        if existing.data:
            print(f"  ⏩ {u['username']} already exists – skipping")
            continue
        db.table("users").insert({
            "username": u["username"],
            "email": u["email"],
            "password_hash": pw_hash,
            "role": u["role"],
        }).execute()
        print(f"  ✅ Created {u['username']} ({u['role']})")

    print("\n🎉 Seed complete!")
    print("Default password for all users: Password1!")


if __name__ == "__main__":
    print("🌱 Seeding ZTS database...\n")
    seed()
