"""Seed default roles into the database. Run via: make seed"""

import asyncio

from sqlalchemy import select

from app.core.config import settings
from app.db.base import async_session_factory
from app.db.models.role import Role

DEFAULT_ROLES = [
    {
        "name": "super_admin",
        "description": "Full system access",
        "permissions": ["*"],
    },
    {
        "name": "admin",
        "description": "Administrative access",
        "permissions": [
            "users:read",
            "users:update",
            "users:ban",
            "users:unban",
            "roles:assign",
            "roles:remove",
            "audit:read",
        ],
    },
    {
        "name": "user",
        "description": "Standard user access",
        "permissions": [
            "profile:read",
            "profile:update",
        ],
    },
]


async def seed() -> None:
    if not settings.ENABLE_RBAC:
        print("RBAC is not enabled. Skipping seed.")
        return

    async with async_session_factory() as session:
        for role_data in DEFAULT_ROLES:
            stmt = select(Role).where(Role.name == role_data["name"])
            result = await session.execute(stmt)
            existing = result.scalar_one_or_none()

            if existing:
                print(f"  Role '{role_data['name']}' already exists, skipping.")
            else:
                role = Role(**role_data)
                session.add(role)
                print(f"  Created role '{role_data['name']}'")

        await session.commit()
    print("Seed complete.")


if __name__ == "__main__":
    asyncio.run(seed())
