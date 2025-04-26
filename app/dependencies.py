from builtins import Exception, dict, str
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import Database
from app.utils.template_manager import TemplateManager
from app.services.email_service import EmailService
from app.services.jwt_service import decode_token
from settings.config import Settings
from fastapi import Depends
from typing import List
from app.services.jwt_service import decode_token, validate_token_and_get_subject, validate_token_and_get_role
from app.services.user_service import UserService
import logging




def get_settings() -> Settings:
    """Return application settings."""
    return Settings()

def get_email_service() -> EmailService:
    template_manager = TemplateManager()
    return EmailService(template_manager=template_manager)

async def get_db() -> AsyncSession:
    """Dependency that provides a database session for each request."""
    async_session_factory = Database.get_session_factory()
    async with async_session_factory() as session:
        try:
            yield session
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
        





# Set up OAuth2 password bearer
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")



async def get_current_user(token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)):
    """
    Dependency that returns the current user based on the JWT token.
    
    Args:
        token: The JWT token from the Authorization header
        db: Database session
        
    Returns:
        User: The current authenticated user
        
    Raises:
        HTTPException: If token is invalid or user not found
    """
    try:
        # Validate token and get subject (email)
        email = validate_token_and_get_subject(token)
        
        # Get user from database
        user = await UserService.get_by_email(db, email)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
                headers={"WWW-Authenticate": "Bearer"}
            )
            
        # Check if user's email is verified
        if not user.email_verified:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Email not verified",
                headers={"WWW-Authenticate": "Bearer"}
            )
            
        # Check if user is locked
        if user.is_locked:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Account is locked",
                headers={"WWW-Authenticate": "Bearer"}
            )
            
        return user
    except HTTPException:
        # Re-raise HTTP exceptions
        raise
    except Exception as e:
        # Log the error and raise a generic exception
        logging.error(f"Error authenticating user: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"}
        )

def require_role(allowed_roles: List[str]):
    """
    Dependency factory that creates a dependency requiring specific roles.
    
    Args:
        allowed_roles: List of roles allowed to access the endpoint
        
    Returns:
        Dependency function that validates user role
    """
    async def role_dependency(token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)):
        try:
            # First validate the token and get the email
            email = validate_token_and_get_subject(token)
            
            # Get role from token
            role = validate_token_and_get_role(token)
            
            # Check if the role is in allowed roles
            if role not in [r.upper() for r in allowed_roles]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions. Required roles: {', '.join(allowed_roles)}"
                )
                
            # Get user from database for completeness
            user = await UserService.get_by_email(db, email)
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not found",
                    headers={"WWW-Authenticate": "Bearer"}
                )
                
            # Return the user for the endpoint to use
            return user
        except HTTPException:
            # Re-raise HTTP exceptions
            raise
        except Exception as e:
            # Log the error and raise a generic exception
            logging.error(f"Error validating role: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate permissions",
                headers={"WWW-Authenticate": "Bearer"}
            )
            
    return role_dependency