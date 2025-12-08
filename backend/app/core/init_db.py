import logging
import secrets
import pymongo
from app.db.mongodb import get_database
from app.models.user import User
from app.core.security import get_password_hash

logger = logging.getLogger(__name__)

async def create_indexes(db):
    """Creates indexes for all collections to ensure performance."""
    logger.info("Creating database indexes...")
    
    # Users
    await db["users"].create_index("username", unique=True)
    await db["users"].create_index("email", unique=True)

    # Projects
    await db["projects"].create_index("owner_id")
    await db["projects"].create_index("team_id")
    await db["projects"].create_index("name")
    await db["projects"].create_index("members.user_id")

    # Teams
    await db["teams"].create_index("members.user_id")

    # Scans
    await db["scans"].create_index("project_id")
    await db["scans"].create_index([("created_at", pymongo.DESCENDING)])
    # Compound index for efficient retrieval of project scans sorted by date
    await db["scans"].create_index([("project_id", pymongo.ASCENDING), ("created_at", pymongo.DESCENDING)])
    
    # Indexes for SBOM analysis (finding components across projects)
    # Required for dependency usage queries.
    await db["scans"].create_index("sbom.components.name")
    await db["scans"].create_index("sbom.components.purl")
    await db["scans"].create_index("sbom.components.version")

    # Analysis Results
    await db["analysis_results"].create_index("scan_id")
    await db["analysis_results"].create_index([("scan_id", pymongo.ASCENDING), ("analyzer_name", pymongo.ASCENDING)])

    # Invitations
    await db["project_invitations"].create_index("token", unique=True)
    await db["project_invitations"].create_index("email")
    
    logger.info("Database indexes created successfully.")

async def init_db():
    db = await get_database()
    
    # Create indexes
    await create_indexes(db)
    
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
