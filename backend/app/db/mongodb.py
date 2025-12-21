from motor.motor_asyncio import AsyncIOMotorClient
from app.core.config import settings
import logging

logger = logging.getLogger(__name__)

class Database:
    client: AsyncIOMotorClient = None

db = Database()

async def get_database():
    return db.client[settings.DATABASE_NAME]

async def connect_to_mongo():
    db.client = AsyncIOMotorClient(settings.MONGODB_URL)
    logger.info("Connected to MongoDB")

async def close_mongo_connection():
    if db.client is not None:
        db.client.close()
        logger.info("Closed MongoDB connection")
