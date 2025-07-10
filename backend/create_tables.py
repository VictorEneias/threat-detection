import asyncio
import os
from database import init_db
import models  # noqa: F401
from modules.user_auth import create_user, get_user_by_username


async def main():
    await init_db()
    init_user = os.getenv("INIT_ADMIN_USER")
    init_pass = os.getenv("INIT_ADMIN_PASS")
    if init_user and init_pass:
        existing = await get_user_by_username(init_user)
        if not existing:
            email = f"{init_user}@example.com"
            await create_user(init_user, email, init_pass, True)
            print("Usuario admin inicial criado.")
    print("Tabelas criadas.")


if __name__ == "__main__":
    asyncio.run(main())
