import asyncio
from getpass import getpass
from modules.admin_auth import create_admin

async def main():
    username = input("Username: ")
    password = getpass("Password: ")
    await create_admin(username, password)
    print("Admin criado com sucesso.")

if __name__ == "__main__":
    asyncio.run(main())
