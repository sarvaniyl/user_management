# User Management System 

This repository contains new features, test cases, and bug fixes for a user management system, focusing on improving data validation, enhancing security, and addressing potential bugs in the codebase.

## QA Issues Resolved

1. **Insufficient Input Validation:** User input validation is limited in several endpoints, particularly for email formats and password complexity requirements. [View code](https://github.com/sarvaniyl/user_management/tree/main/app/schemas/user_schemas.py) | [Issue #1](https://github.com/sarvaniyl/user_management/issues/1)

2. **Improper JWT Token Validation:** The JWT validation doesn't check for token expiration or signature properly in some cases, which could lead to security vulnerabilities. [View code](https://github.com/sarvaniyl/user_management/tree/main/app/services/jwt_service.py) | [Issue #3](https://github.com/sarvaniyl/user_management/issues/3)

3. **No Input Sanitization:** User input isn't properly sanitized before being used in database queries, potentially leading to injection attacks. [View code](https://github.com/sarvaniyl/user_management/tree/main/app/schemas/user_schemas.py) | [Issue #4](https://github.com/sarvaniyl/user_management/issues/4)

4. **Missing Database Indexing:** No indexes are defined on frequently queried fields like email and nickname, which could lead to performance issues as the database grows. [View code](https://github.com/sarvaniyl/user_management/tree/main/app/models/user_model.py) | [Issue #6](https://github.com/sarvaniyl/user_management/issues/6)

5. **Improper Error Handling in Email Service:** The email_service.py directly calls SMTP methods without proper exception handling, which could lead to unhandled exceptions if email sending fails. [View code](https://github.com/sarvaniyl/user_management/tree/main/app/services/email_service.py) | [Issue #7](https://github.com/sarvaniyl/user_management/issues/7)

## PyTest Test Suite 

The test suite uses PyTest with the `pytest-asyncio` plugin to perform asynchronous testing. These tests cover various aspects of the web application, including user authentication, registration, password management, and user profile updates. [View test code](https://github.com/sarvaniyl/user_management/tree/main/tests/test_api/test_users_api.py)

### User Authentication Tests

#### `test_account_locking(async_client, verified_user, db_session)`
- Verifies that a user account is locked after exceeding the maximum allowed failed login attempts
- Simulates multiple failed login attempts with an incorrect password
- Asserts that after the configured number of failed attempts, subsequent login attempts, even with the correct password, are rejected
- Checks for the correct HTTP status code (400) and error message ("Account locked")

### User Registration Tests

#### `test_register_with_valid_data(async_client, email_service)`
- Tests the user registration endpoint with valid user data
- Submits a registration request with a unique nickname, email, and a strong password
- Asserts that the registration is successful (status code 201) or that the input data is rejected due to validation issues (status code 422)
- On successful registration, it verifies the presence of an 'id' in the response and that the returned email matches the submitted email

### User Verification Tests

#### `test_verify_user_with_valid_token(async_client, unverified_user)`
- Tests the user verification endpoint with a valid verification token
- Attempts to verify a user account using a token generated for an unverified user
- Anticipates a successful verification (status code 200) or a 404 if the verification route is not found
- Upon successful verification, it checks for a 'message' key in the response

#### `test_verify_user_with_invalid_token(async_client)`
- Tests the user verification endpoint with an invalid verification token
- Calls the verification endpoint with a deliberately invalid token
- Expects the server to respond with either a 400 (Bad Request) or a 404 (Not Found)

### Password Management Tests

#### `test_request_password_reset(async_client, verified_user, email_service)`
- Tests the endpoint for requesting a password reset
- Submits a password reset request with the email address of a verified user
- Expects a successful request (status code 200) or a 404 if the endpoint is not found
- If the request is successful, it verifies that the `send_reset_password_email` method of the mocked `email_service` was called

#### `test_reset_password_with_valid_token(async_client, verified_user)`
- Tests the endpoint for resetting a user's password using a valid token
- Submits a new password along with the token to the reset password endpoint
- Expects a successful password reset (status code 200) or a 404 if the endpoint is not found
- On success, it verifies the presence of a 'message' in the response

### User Profile Tests

#### `test_user_update_own_profile(async_client, verified_user, user_token)`
- Tests the ability of a user to update their own profile information
- Submits updated data (e.g., a new bio) with a valid user token
- Checks for a successful update (status code 200) and verifies that the data is updated correctly
- Handles potential 403 (Forbidden) or 404 (Not Found) responses

#### `test_manager_update_user_role(async_client, verified_user, manager_token)`
- Tests the ability of a manager to update another user's role
- Submits a request to update a user's role with a valid manager token
- Expects a successful update (status code 200) and verifies that the role is updated
- Handles potential 401 (Unauthorized), 403 (Forbidden), or 404 (Not Found) responses

#### `test_logout_user(async_client, verified_user, user_token)`
- Tests the user logout functionality
- Submits a logout request with a valid user token
- Checks for a successful logout (status code 200) and verifies that the token is invalidated

#### `test_get_current_user_profile(async_client, verified_user, user_token)`
- Tests the endpoint to retrieve the current user's profile
- Sends a request with a valid user token
- Asserts a successful response (status code 200) and verifies that the returned profile data contains the user's 'id' and 'email'
- It also compares the returned 'id' and 'email' with the expected values from the `verified_user` fixture

## Features Developed

### User Search and Filtering
**Description:** Implemented search and filtering capabilities to allow administrators to easily find and manage users based on various criteria.

### User Profile Management
**Description:** Enhanced the user profile management functionality to allow users to update their profile fields and enable managers and admins to upgrade users to professional status.

## DockerHub Link

You can view the user management tags on DockerHub here: [View DockerHub Repository](https://hub.docker.com/repository/docker/sarvani07/user_management/general)
