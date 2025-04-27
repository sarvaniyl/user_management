import pytest
from unittest.mock import AsyncMock, patch
from httpx import AsyncClient
from uuid import uuid4
from app.models.user_model import User, UserRole
from app.utils.nickname_gen import generate_nickname
from app.utils.security import hash_password, generate_verification_token
from urllib.parse import urlencode


@pytest.mark.asyncio
async def test_email_verification_flow(async_client, unverified_user):
    """
    Test 1: Test email verification flow
    Verifies that a user can verify their email with a valid token
    """
    # Generate verification URL with token
    token = unverified_user.verification_token
    
    # Access the verification endpoint
    response = await async_client.get(f"/verify-email/{unverified_user.id}/{token}")
    
    # Assert success and redirection
    assert response.status_code == 200
    
    # Verify user has been updated in database
    headers = {"Authorization": f"Bearer {await get_admin_token(async_client)}"}
    user_response = await async_client.get(f"/users/{unverified_user.id}", headers=headers)
    
    assert user_response.status_code == 200
    user_data = user_response.json()
    assert user_data["email_verified"] is True
    assert user_data["role"] == UserRole.AUTHENTICATED.name


@pytest.mark.asyncio
async def test_account_locking(async_client, verified_user, db_session):
    """
    Test 2: Test account locking after multiple failed login attempts
    Verifies account gets locked after too many failed login attempts
    """
    # Attempt to login with incorrect password multiple times
    form_data = {
        "username": verified_user.email,
        "password": "WrongPassword123!"
    }
    
    # Get max attempts from settings
    from app.dependencies import get_settings
    settings = get_settings()
    max_attempts = settings.max_login_attempts
    
    # Make failed login attempts
    for i in range(max_attempts):
        response = await async_client.post(
            "/login/", 
            data=urlencode(form_data), 
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        assert response.status_code == 401
    
    # One more attempt should result in account locked
    response = await async_client.post(
        "/login/", 
        data=urlencode(form_data), 
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    
    assert response.status_code == 400
    assert "Account locked" in response.json().get("detail", "")
    
    # Verify that even with correct password, login fails
    form_data["password"] = "MySuperPassword$1234"
    response = await async_client.post(
        "/login/", 
        data=urlencode(form_data), 
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert response.status_code == 400
    assert "Account locked" in response.json().get("detail", "")


@pytest.mark.asyncio
async def test_role_based_access_control(async_client, verified_user, admin_user, manager_user):
    """
    Test 3: Test role-based access control to protected endpoints
    """
    # Generate tokens for different roles
    admin_token = await get_token_for_user(async_client, admin_user.email)
    manager_token = await get_token_for_user(async_client, manager_user.email) 
    user_token = await get_token_for_user(async_client, verified_user.email)
    
    # Test accessing user list endpoint with different roles
    # Admin should have full access
    admin_response = await async_client.get(
        "/users/", 
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert admin_response.status_code == 200
    
    # Manager should have access
    manager_response = await async_client.get(
        "/users/", 
        headers={"Authorization": f"Bearer {manager_token}"}
    )
    assert manager_response.status_code == 200
    
    # Regular user should not have access
    user_response = await async_client.get(
        "/users/", 
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert user_response.status_code == 403
    
    # Test user modification endpoints
    user_id = str(verified_user.id)
    update_data = {"first_name": "New First Name"}
    
    # Admin should be able to update any user
    admin_update = await async_client.put(
        f"/users/{user_id}", 
        json=update_data,
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert admin_update.status_code == 200
    
    # Regular user should not be able to update other users
    user_update = await async_client.put(
        f"/users/{admin_user.id}", 
        json=update_data,
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert user_update.status_code == 403


@pytest.mark.asyncio
async def test_user_search_filtering(async_client, admin_token, verified_user, manager_user):
    """
    Test 4: Test for user search and filtering functionality
    """
    # Test filtering by email
    email_response = await async_client.get(
        f"/users/?email={verified_user.email}",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert email_response.status_code == 200
    email_data = email_response.json()
    assert len(email_data["items"]) >= 1
    assert any(user["email"] == verified_user.email for user in email_data["items"])
    
    # Test filtering by role
    role_response = await async_client.get(
        f"/users/?role={UserRole.MANAGER.name}",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert role_response.status_code == 200
    role_data = role_response.json()
    assert len(role_data["items"]) >= 1
    assert any(user["role"] == UserRole.MANAGER.name for user in role_data["items"])
    
    # Test filtering by verification status
    verified_response = await async_client.get(
        "/users/?verified=true",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert verified_response.status_code == 200
    verified_data = verified_response.json()
    assert len(verified_data["items"]) >= 1


@pytest.mark.asyncio
async def test_password_reset_flow(async_client, verified_user, db_session):
    """
    Test 5: Test for password reset flow
    """
    # Step 1: Request password reset token
    request_response = await async_client.post(
        "/password-reset/request/",
        json={"email": verified_user.email}
    )
    assert request_response.status_code == 200
    
    # Step 2: In a real test, we'd extract the token from the email
    # For this test, we'll mock the token retrieval
    # Update the user with a reset token directly
    from app.services.user_service import UserService
    reset_token = "test-reset-token"
    await UserService.update(
        db_session, 
        verified_user.id, 
        {"password_reset_token": reset_token}
    )
    
    # Step 3: Use the token to reset password
    reset_response = await async_client.post(
        "/password-reset/confirm/",
        json={
            "user_id": str(verified_user.id),
            "token": reset_token,
            "new_password": "NewSecurePassword123!"
        }
    )
    assert reset_response.status_code == 200
    
    # Step 4: Verify can login with new password
    form_data = {
        "username": verified_user.email,
        "password": "NewSecurePassword123!"
    }
    login_response = await async_client.post(
        "/login/", 
        data=urlencode(form_data), 
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert login_response.status_code == 200
    assert "access_token" in login_response.json()


@pytest.mark.asyncio
async def test_user_profile_update(async_client, verified_user):
    """
    Test 6: Test for user profile update functionality
    """
    # Get token for the user
    user_token = await get_token_for_user(async_client, verified_user.email)
    
    # Update profile data
    profile_data = {
        "first_name": "Updated",
        "last_name": "User",
        "bio": "This is my updated bio",
        "linkedin_profile_url": "https://linkedin.com/in/updated-user",
        "github_profile_url": "https://github.com/updated-user"
    }
    
    # Update user profile
    update_response = await async_client.put(
        f"/users/{verified_user.id}",
        json=profile_data,
        headers={"Authorization": f"Bearer {user_token}"}
    )
    
    # Check if user can update their own profile
    # If the user can't update their own profile (based on your RBAC logic),
    # this should be 403 instead
    expected_status = 200 if self_update_allowed(verified_user) else 403
    assert update_response.status_code == expected_status
    
    if expected_status == 200:
        updated_data = update_response.json()
        assert updated_data["first_name"] == profile_data["first_name"]
        assert updated_data["last_name"] == profile_data["last_name"]
        assert updated_data["bio"] == profile_data["bio"]
        assert updated_data["linkedin_profile_url"] == profile_data["linkedin_profile_url"]
        assert updated_data["github_profile_url"] == profile_data["github_profile_url"]


@pytest.mark.asyncio
async def test_user_deletion(async_client, admin_token, db_session):
    """
    Test 7: Test for user deletion
    """
    # Create a new user to be deleted
    from app.services.user_service import UserService
    from app.services.email_service import EmailService
    
    # Mock email service
    email_service = AsyncMock(spec=EmailService)
    email_service.send_verification_email.return_value = True
    
    user_data = {
        "email": f"delete-test-{uuid4()}@example.com",
        "password": "DeleteTest123!",
        "role": UserRole.AUTHENTICATED.name
    }
    
    new_user = await UserService.create(db_session, user_data, email_service)
    assert new_user is not None
    
    # Delete the user
    delete_response = await async_client.delete(
        f"/users/{new_user.id}",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert delete_response.status_code == 204
    
    # Verify user is deleted
    get_response = await async_client.get(
        f"/users/{new_user.id}",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert get_response.status_code == 404


@pytest.mark.asyncio
async def test_pagination_in_user_listing(async_client, admin_token):
    """
    Test 8: Test for pagination in user listing
    """
    # Test first page with smaller page size
    page1_response = await async_client.get(
        "/users/?page=1&per_page=2",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert page1_response.status_code == 200
    page1_data = page1_response.json()
    assert len(page1_data["items"]) <= 2
    assert page1_data["page"] == 1
    assert page1_data["per_page"] == 2
    
    # Test second page
    page2_response = await async_client.get(
        "/users/?page=2&per_page=2",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert page2_response.status_code == 200
    page2_data = page2_response.json()
    assert page2_data["page"] == 2
    
    # Verify different users on different pages
    if len(page1_data["items"]) > 0 and len(page2_data["items"]) > 0:
        page1_ids = [user["id"] for user in page1_data["items"]]
        page2_ids = [user["id"] for user in page2_data["items"]]
        # Check that pages don't have overlapping users
        assert not any(id in page2_ids for id in page1_ids)


@pytest.mark.asyncio
async def test_email_verification_token_validation(async_client, unverified_user):
    """
    Test 9: Test for email verification token validation
    """
    # Test with invalid token
    invalid_token_response = await async_client.get(
        f"/verify-email/{unverified_user.id}/invalid-token"
    )
    assert invalid_token_response.status_code == 400
    assert "Invalid verification token" in invalid_token_response.text
    
    # Test with valid token
    valid_token = unverified_user.verification_token
    valid_token_response = await async_client.get(
        f"/verify-email/{unverified_user.id}/{valid_token}"
    )
    assert valid_token_response.status_code == 200
    
    # Test with already verified user
    already_verified_response = await async_client.get(
        f"/verify-email/{unverified_user.id}/{valid_token}"
    )
    assert already_verified_response.status_code == 400
    assert "Email already verified" in already_verified_response.text


@pytest.mark.asyncio
async def test_error_handling_when_email_service_fails(async_client, db_session):
    """
    Test 10: Test for error handling when email service fails
    """
    # Create test data
    user_data = {
        "email": f"email-fail-{uuid4()}@example.com",
        "password": "SecurePassword123!",
        "role": UserRole.ANONYMOUS.name
    }
    
    # Mock the email service to simulate failure
    with patch("app.services.email_service.EmailService.send_verification_email", 
              side_effect=Exception("SMTP server connection failed")):
        
        # Attempt to register user
        register_response = await async_client.post(
            "/register/",
            json=user_data
        )
        
        # Check if registration still works but with proper error handling
        assert register_response.status_code in [201, 500]
        
        if register_response.status_code == 201:
            # If the API is designed to continue despite email failures
            assert "id" in register_response.json()
        else:
            # If the API is designed to fail if email sending fails
            assert "error" in register_response.json()


# Helper functions for the tests

async def get_admin_token(async_client):
    """Helper function to get an admin token"""
    form_data = {
        "username": "admin@example.com",
        "password": "AdminSecurePassword123!"
    }
    response = await async_client.post(
        "/login/", 
        data=urlencode(form_data), 
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    return response.json()["access_token"]


async def get_token_for_user(async_client, email, password="MySuperPassword$1234"):
    """Helper function to get token for a specific user"""
    form_data = {
        "username": email,
        "password": password
    }
    response = await async_client.post(
        "/login/", 
        data=urlencode(form_data), 
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    return response.json()["access_token"]


def self_update_allowed(user):
    """Check if user is allowed to update their own profile based on your app's logic"""
    # This implementation depends on your application's RBAC logic
    # Either check your code or replace with the correct implementation
    return user.role in [UserRole.AUTHENTICATED, UserRole.MANAGER, UserRole.ADMIN]