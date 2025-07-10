import asyncio
from getpass import getpass
from modules.user_auth import create_user

async def main():
    username = input("Username: ")
    email = input("Email: ")
    password = getpass("Password: ")
    await create_user(username, email, password, True)
    print("Admin criado com sucesso.")

if __name__ == "__main__":
    asyncio.run(main())