"""
Database module for MongoDB connection management.
"""

from app.db.mongodb import (
    close_mongo_connection,
    connect_to_mongo,
    db,
    get_database,
)

__all__ = [
    "db",
    "get_database",
    "connect_to_mongo",
    "close_mongo_connection",
]
