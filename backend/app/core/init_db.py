import logging
import secrets
from app.db.mongodb import get_database
from app.models.user import User
from app.core.security import get_password_hash

logger = logging.getLogger(__name__)

async def init_db():
    db = await get_database()
    user_collection = db["users"]
    
    # Check if any user exists
    if await user_collection.count_documents({}) == 0:
        logger.info("No users found. Creating initial admin user.")
        
        # Generate a secure random password
        password = secrets.token_urlsafe(16)
        hashed_password = get_password_hash(password)
        
        # Create the admin user with all permissions
        user = User(
            username="admin",
            email="admin@example.com",
            hashed_password=hashed_password,
            permissions=["*"]
        )
        
        # Insert into database
        await user_collection.insert_one(user.model_dump(by_alias=True))
        
        # Print credentials to logs
        print("\n" + "=" * 60)
        print("INITIAL ADMIN USER CREATED")
        print("-" * 60)
        print(f"Username: {user.username}")
        print(f"Email:    {user.email}")
        print(f"Password: {password}")
        print("-" * 60)
        print("PLEASE CHANGE THIS PASSWORD IMMEDIATELY AFTER LOGIN!")
        print("=" * 60 + "\n")
    else:
        logger.info("Users already exist. Skipping initial user creation.")
