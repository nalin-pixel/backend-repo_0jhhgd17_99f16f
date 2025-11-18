"""
Database Helper Functions

MongoDB helper functions ready to use in your backend code.
Import and use these functions in your API endpoints for database operations.
"""

from datetime import datetime, timezone
import os
from typing import Union

from dotenv import load_dotenv
from pydantic import BaseModel

# Prefer real MongoDB if available, otherwise fall back to in-memory mongomock
from pymongo import MongoClient
try:
    import mongomock  # type: ignore
except Exception:  # pragma: no cover
    mongomock = None  # Will remain None if not installed

# Load environment variables from .env file
load_dotenv()

_client = None
_db = None
DB_MODE = "uninitialized"  # real | mock | uninitialized

# Read env
DATABASE_URL = os.getenv("DATABASE_URL")
DATABASE_NAME = os.getenv("DATABASE_NAME")

# Initialize client / db
if DATABASE_URL and DATABASE_NAME:
    # Real MongoDB
    _client = MongoClient(DATABASE_URL)
    _db = _client[DATABASE_NAME]
    DB_MODE = "real"
else:
    # Fallback to in-memory DB for development/preview so the app works out of the box
    if mongomock is None:
        # If mongomock isn't available, keep _db as None so /test can show helpful error
        DB_MODE = "uninitialized"
    else:
        _client = mongomock.MongoClient()
        _db = _client[os.getenv("DATABASE_NAME", "devdb")]
        DB_MODE = "mock"

# Public handle used by the rest of the app
# (Keeping the original name `db` to avoid touching other modules)
db = _db

# Helper functions for common database operations

def create_document(collection_name: str, data: Union[BaseModel, dict]):
    """Insert a single document with timestamp"""
    if db is None:
        raise Exception(
            "Database not available. Set DATABASE_URL/DATABASE_NAME or enable mongomock."
        )

    # Convert Pydantic model to dict if needed
    if isinstance(data, BaseModel):
        data_dict = data.model_dump()
    else:
        data_dict = dict(data)

    data_dict["created_at"] = datetime.now(timezone.utc)
    data_dict["updated_at"] = datetime.now(timezone.utc)

    result = db[collection_name].insert_one(data_dict)
    return str(result.inserted_id)


def get_documents(collection_name: str, filter_dict: dict | None = None, limit: int | None = None):
    """Get documents from collection"""
    if db is None:
        raise Exception(
            "Database not available. Set DATABASE_URL/DATABASE_NAME or enable mongomock."
        )

    cursor = db[collection_name].find(filter_dict or {})
    if limit:
        cursor = cursor.limit(limit)

    return list(cursor)
