# app/services/jwt_service.py
from builtins import dict, str
import jwt
from datetime import datetime, timedelta
from fastapi import HTTPException, status
from settings.config import settings
import logging
import uuid

logger = logging.getLogger(__name__)

def create_access_token(*, data: dict, expires_delta: timedelta = None):
    """
    Create a JWT access token with proper payload and signature.
    
    Args:
        data: Dictionary containing data to encode in the token
        expires_delta: Optional timedelta for token expiration
        
    Returns:
        str: Encoded JWT token
    """
    to_encode = data.copy()
    # Convert role to uppercase before encoding the JWT
    if 'role' in to_encode:
        to_encode['role'] = to_encode['role'].upper()
        
    # Add standard JWT claims
    now = datetime.utcnow()
    to_encode.update({
        "iat": now,  # Issued at
        "nbf": now,  # Not valid before
    })
    
    # Set expiration time
    expire = now + (expires_delta if expires_delta else timedelta(minutes=settings.access_token_expire_minutes))
    to_encode.update({"exp": expire})
    
    # Add token ID for additional security
    to_encode.update({"jti": str(uuid.uuid4())})
    
    try:
        encoded_jwt = jwt.encode(
            to_encode, 
            settings.jwt_secret_key, 
            algorithm=settings.jwt_algorithm
        )
        return encoded_jwt
    except Exception as e:
        logger.error(f"Error creating JWT token: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not create access token"
        )

def decode_token(token: str, verify_exp: bool = True):
    """
    Decode and validate a JWT token.
    
    Args:
        token: The JWT token to decode
        verify_exp: Whether to verify token expiration (default: True)
        
    Returns:
        dict: Decoded token payload
        
    Raises:
        HTTPException: With appropriate status code and detail message if validation fails
    """
    try:
        # Explicitly specify all verification parameters
        decoded = jwt.decode(
            token, 
            settings.jwt_secret_key, 
            algorithms=[settings.jwt_algorithm],
            options={
                "verify_signature": True,
                "verify_exp": verify_exp,
                "verify_nbf": True,
                "verify_iat": True,
                "require": ["exp", "iat", "nbf", "sub", "role"]
            }
        )
        return decoded
    except jwt.ExpiredSignatureError:
        logger.warning("Expired JWT token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"}
        )
    except jwt.InvalidTokenError as e:
        logger.warning(f"Invalid JWT token: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"}
        )
    except Exception as e:
        logger.error(f"Unexpected error decoding JWT token: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"}
        )

def validate_token_and_get_subject(token: str):
    """
    Validate token and extract the subject (user identifier).
    
    Args:
        token: The JWT token
        
    Returns:
        str: The subject claim from the token
        
    Raises:
        HTTPException: If token is invalid
    """
    payload = decode_token(token)
    subject = payload.get("sub")
    if not subject:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing subject claim",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return subject

def validate_token_and_get_role(token: str):
    """
    Validate token and extract the role.
    
    Args:
        token: The JWT token
        
    Returns:
        str: The role claim from the token
        
    Raises:
        HTTPException: If token is invalid or missing role
    """
    payload = decode_token(token)
    role = payload.get("role")
    if not role:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing role claim",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return role

def extract_token_from_header(authorization: str):
    """
    Extract the token from the Authorization header.
    
    Args:
        authorization: The Authorization header value
        
    Returns:
        str: The extracted token
        
    Raises:
        HTTPException: If header format is invalid
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header missing",
            headers={"WWW-Authenticate": "Bearer"}
        )
        
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication scheme",
            headers={"WWW-Authenticate": "Bearer"}
        )
        
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing",
            headers={"WWW-Authenticate": "Bearer"}
        )
        
    return token
