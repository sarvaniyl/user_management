from builtins import Exception, bool, classmethod, int, str
from datetime import datetime, timezone
import secrets
import html
from typing import Optional, Dict, List, Any
from pydantic import ValidationError
from sqlalchemy import func, null, update, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from app.dependencies import get_email_service, get_settings
from app.models.user_model import User
from app.schemas.user_schemas import UserCreate, UserUpdate
from app.utils.nickname_gen import generate_nickname
from app.utils.security import generate_verification_token, hash_password, verify_password
from uuid import UUID
from app.services.email_service import EmailService
from app.models.user_model import UserRole
import logging
import re

settings = get_settings()
logger = logging.getLogger(__name__)

class UserService:
    @classmethod
    def sanitize_input(cls, value: Any) -> Any:
        """Sanitize input to prevent injection attacks"""
        if isinstance(value, str):
            # Sanitize string inputs
            # HTML escape to prevent XSS
            sanitized = html.escape(value)
            # Remove potentially dangerous patterns
            sanitized = re.sub(r'[\'";`]', '', sanitized)
            return sanitized
        elif isinstance(value, dict):
            # Recursively sanitize dictionary values
            return {k: cls.sanitize_input(v) for k, v in value.items()}
        elif isinstance(value, list):
            # Recursively sanitize list items
            return [cls.sanitize_input(item) for item in value]
        else:
            # Return other types unchanged (numbers, booleans, etc.)
            return value

    @classmethod
    async def _execute_query(cls, session: AsyncSession, query):
        try:
            result = await session.execute(query)
            await session.commit()
            return result
        except SQLAlchemyError as e:
            logger.error(f"Database error: {e}")
            await session.rollback()
            return None

    @classmethod
    async def _fetch_user(cls, session: AsyncSession, **filters) -> Optional[User]:
        # Sanitize filter values
        sanitized_filters = {k: cls.sanitize_input(v) for k, v in filters.items()}
        query = select(User).filter_by(**sanitized_filters)
        result = await cls._execute_query(session, query)
        return result.scalars().first() if result else None

    @classmethod
    async def get_by_id(cls, session: AsyncSession, user_id: UUID) -> Optional[User]:
        # UUID is a safe type and doesn't need sanitization
        return await cls._fetch_user(session, id=user_id)

    @classmethod
    async def get_by_nickname(cls, session: AsyncSession, nickname: str) -> Optional[User]:
        # Sanitize nickname
        sanitized_nickname = cls.sanitize_input(nickname)
        return await cls._fetch_user(session, nickname=sanitized_nickname)

    @classmethod
    async def get_by_email(cls, session: AsyncSession, email: str) -> Optional[User]:
        # Sanitize email
        sanitized_email = cls.sanitize_input(email)
        return await cls._fetch_user(session, email=sanitized_email)

    @classmethod
    async def create(cls, session: AsyncSession, user_data: Dict[str, str], email_service: EmailService) -> Optional[User]:
        try:
            # Sanitize all user inputs
            sanitized_data = cls.sanitize_input(user_data)
            
            # Let Pydantic model validate the sanitized data
            validated_data = UserCreate(**sanitized_data).model_dump()
            
            existing_user = await cls.get_by_email(session, validated_data['email'])
            if existing_user:
                logger.error("User with given email already exists.")
                return None
                
            validated_data['hashed_password'] = hash_password(validated_data.pop('password'))
            new_user = User(**validated_data)
            new_nickname = generate_nickname()
            while await cls.get_by_nickname(session, new_nickname):
                new_nickname = generate_nickname()
            new_user.nickname = new_nickname
            logger.info(f"User Role: {new_user.role}")
            user_count = await cls.count(session)
            new_user.role = UserRole.ADMIN if user_count == 0 else UserRole.ANONYMOUS            
            if new_user.role == UserRole.ADMIN:
                new_user.email_verified = True
            else:
                new_user.verification_token = generate_verification_token()
                await email_service.send_verification_email(new_user)

            session.add(new_user)
            await session.commit()
            return new_user
        except ValidationError as e:
            logger.error(f"Validation error during user creation: {e}")
            return None

    @classmethod
    async def update(cls, session: AsyncSession, user_id: UUID, update_data: Dict[str, str]) -> Optional[User]:
        try:
            # Sanitize all user inputs
            sanitized_data = cls.sanitize_input(update_data)
            
            # Let Pydantic model validate the sanitized data
            validated_data = UserUpdate(**sanitized_data).model_dump(exclude_unset=True)

            if 'password' in validated_data:
                validated_data['hashed_password'] = hash_password(validated_data.pop('password'))
                
            # Use parameterized query with sanitized data
            query = update(User).where(User.id == user_id).values(**validated_data).execution_options(synchronize_session="fetch")
            await cls._execute_query(session, query)
            
            updated_user = await cls.get_by_id(session, user_id)
            if updated_user:
                session.refresh(updated_user)  # Explicitly refresh the updated user object
                logger.info(f"User {user_id} updated successfully.")
                return updated_user
            else:
                logger.error(f"User {user_id} not found after update attempt.")
            return None
        except Exception as e:  # Broad exception handling for debugging
            logger.error(f"Error during user update: {e}")
            return None

    @classmethod
    async def delete(cls, session: AsyncSession, user_id: UUID) -> bool:
        user = await cls.get_by_id(session, user_id)
        if not user:
            logger.info(f"User with ID {user_id} not found.")
            return False
        await session.delete(user)
        await session.commit()
        return True

    @classmethod
    async def list_users(cls, session: AsyncSession, skip: int = 0, limit: int = 10) -> List[User]:
        # Sanitize pagination parameters
        sanitized_skip = max(0, int(skip))  # Ensure non-negative
        sanitized_limit = min(100, max(1, int(limit)))  # Bound between 1 and 100
        
        query = select(User).offset(sanitized_skip).limit(sanitized_limit)
        result = await cls._execute_query(session, query)
        return result.scalars().all() if result else []

    @classmethod
    async def register_user(cls, session: AsyncSession, user_data: Dict[str, str], get_email_service) -> Optional[User]:
        return await cls.create(session, user_data, get_email_service)
    
    @classmethod
    async def login_user(cls, session: AsyncSession, email: str, password: str) -> Optional[User]:
        # Sanitize email
        sanitized_email = cls.sanitize_input(email)
        
        user = await cls.get_by_email(session, sanitized_email)
        if user:
            if user.email_verified is False:
                return None
            if user.is_locked:
                return None
            if verify_password(password, user.hashed_password):
                user.failed_login_attempts = 0
                user.last_login_at = datetime.now(timezone.utc)
                session.add(user)
                await session.commit()
                return user
            else:
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= settings.max_login_attempts:
                    user.is_locked = True
                session.add(user)
                await session.commit()
        return None

    @classmethod
    async def is_account_locked(cls, session: AsyncSession, email: str) -> bool:
        # Sanitize email
        sanitized_email = cls.sanitize_input(email)
        
        user = await cls.get_by_email(session, sanitized_email)
        return user.is_locked if user else False

    @classmethod
    async def reset_password(cls, session: AsyncSession, user_id: UUID, new_password: str) -> bool:
        # Sanitize password
        sanitized_password = cls.sanitize_input(new_password)
        
        hashed_password = hash_password(sanitized_password)
        user = await cls.get_by_id(session, user_id)
        if user:
            user.hashed_password = hashed_password
            user.failed_login_attempts = 0  # Resetting failed login attempts
            user.is_locked = False  # Unlocking the user account, if locked
            session.add(user)
            await session.commit()
            return True
        return False

    @classmethod
    async def verify_email_with_token(cls, session: AsyncSession, user_id: UUID, token: str) -> bool:
        # Sanitize token
        sanitized_token = cls.sanitize_input(token)
        
        user = await cls.get_by_id(session, user_id)
        if user and user.verification_token == sanitized_token:
            user.email_verified = True
            user.verification_token = None  # Clear the token once used
            user.role = UserRole.AUTHENTICATED
            session.add(user)
            await session.commit()
            return True
        return False

    @classmethod
    async def count(cls, session: AsyncSession) -> int:
        """
        Count the number of users in the database.

        :param session: The AsyncSession instance for database access.
        :return: The count of users.
        """
        query = select(func.count()).select_from(User)
        result = await session.execute(query)
        count = result.scalar()
        return count
    
    @classmethod
    async def unlock_user_account(cls, session: AsyncSession, user_id: UUID) -> bool:
        user = await cls.get_by_id(session, user_id)
        if user and user.is_locked:
            user.is_locked = False
            user.failed_login_attempts = 0  # Optionally reset failed login attempts
            session.add(user)
            await session.commit()
            return True
        return False
    @classmethod
    async def update_professional_status(cls, session: AsyncSession, user_id: UUID, is_professional: bool) -> Optional[User]:
        """
        Update a user's professional status and record the timestamp of the change.
        
        Args:
            session: The database session
            user_id: The UUID of the user to update
            is_professional: Boolean indicating whether the user should have professional status
            
        Returns:
            The updated User object if successful, None otherwise
        """
        try:
            user = await cls.get_by_id(session, user_id)
            if not user:
                logger.error(f"User {user_id} not found when updating professional status.")
                return None
                
            user.is_professional = is_professional
            user.professional_status_updated_at = datetime.now(timezone.utc)
            
            session.add(user)
            await session.commit()
            await session.refresh(user)
            
            logger.info(f"Professional status for user {user_id} updated to {is_professional}")
            return user
        except Exception as e:
            logger.error(f"Error updating professional status for user {user_id}: {e}")
            await session.rollback()
            return None