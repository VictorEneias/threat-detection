from motor.motor_asyncio import AsyncIOMotorClient
import os
import bcrypt

client = AsyncIOMotorClient(os.getenv("MONGODB_URI", "mongodb://localhost:27017"))
db = client.cvedb
admins = db.admins

async def create_admin(username: str, password: str) -> None:
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    await admins.insert_one({"username": username, "password": hashed.decode()})

async def verify_admin(username: str, password: str) -> bool:
    doc = await admins.find_one({"username": username})
    if not doc:
        return False
    return bcrypt.checkpw(password.encode(), doc["password"].encode())
