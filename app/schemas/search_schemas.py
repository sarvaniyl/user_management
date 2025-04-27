from builtins import bool, int, str
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field
from app.models.user_model import UserRole

class UserSearchParams(BaseModel):
    """Parameters for searching and filtering users"""
    search: Optional[str] = Field(None, 
                                 description="Search term for email, nickname, first or last name")
    role: Optional[UserRole] = Field(None, 
                                    description="Filter by user role")
    is_verified: Optional[bool] = Field(None, 
                                       description="Filter by email verification status")
    is_locked: Optional[bool] = Field(None, 
                                     description="Filter by account lock status")
    is_professional: Optional[bool] = Field(None, 
                                          description="Filter by professional status")
    date_from: Optional[datetime] = Field(None, 
                                         description="Filter users created after this date")
    date_to: Optional[datetime] = Field(None, 
                                       description="Filter users created before this date")
    sort_by: str = Field("created_at", 
                        description="Field to sort by: created_at, updated_at, email, nickname, last_login_at")
    sort_order: str = Field("desc", 
                           description="Sort order: asc or desc")
    page: int = Field(1, ge=1, 
                     description="Page number")
    per_page: int = Field(10, ge=1, le=100, 
                         description="Number of items per page")
    
    class Config:
        json_schema_extra = {
            "example": {
                "search": "john",
                "role": "AUTHENTICATED",
                "is_verified": True,
                "is_locked": False,
                "is_professional": True,
                "date_from": "2023-01-01T00:00:00Z",
                "date_to": "2023-12-31T23:59:59Z",
                "sort_by": "created_at",
                "sort_order": "desc",
                "page": 1,
                "per_page": 10
            }
        }