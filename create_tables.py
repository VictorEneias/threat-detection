import asyncio
from database import init_db

async def main():
    await init_db()
    print("Tabelas criadas.")

if __name__ == "__main__":
    asyncio.run(main())
