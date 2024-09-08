# Node.js Authentication

A Node.js authentication system built with Express, JWT, Passport, Mongoose, and bcrypt. The project supports authentication with Google OAuth 2.0 and includes features like email verification, password reset, and token-based authentication with JWT.

## Features

- **Local Authentication:** Users can register, log in, and authenticate using JWT.
- **Google OAuth 2.0:** Users can log in using their Google accounts.
- **JWT-based Authentication:** Secure authentication using access and refresh tokens.
- **Email Verification:** Users receive an email with a token for account verification.
- **Password Reset:** Allows users to reset their passwords by sending an email with a reset token.
- **Express Sessions:** Session management with Express for handling user sessions securely.
- **Secure Password Hashing:** Uses bcrypt to hash passwords for secure storage.
- **Environment Configurations:** Easily customizable through `.env` files.

## Postman Documentation

The full API documentation is available on Postman:

[Postman - View API Documentation](https://documenter.getpostman.com/view/21892829/2sAXjRWA3t)

You can use this to test the different endpoints of the project, such as registration, login, and token-based authentication.

## Getting Started

## Prerequisites

- **Node.js** (v16 or later)
- **MongoDB** (local or cloud)
- **Google OAuth Credentials** (Client ID & Secret)

## Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/vatsalpipalava/Nodejs-Authentication.git
cd Nodejs-Authentication
```
### Step 2: Create and Configure the Environment File

```bash
cp .env.example .env
```

### Step 3: Install Dependencies

```bash
npm install
```

### Step 4: Run the Development Server

```bash
npm run dev
```


## API Endpoints

### User Authentication

| Method | Endpoint                   | Description                      |
|--------|-----------------------------|----------------------------------|
| POST   | `/api/v1/user/register`      | Register a new user              |
| POST   | `/api/v1/user/login`         | Log in with email and password   |
| POST   | `/api/v1/user/logout`        | Log out from the system          |
| POST   | `/api/v1/user/google`        | Authenticate with Google OAuth   |

### Token Management

| Method | Endpoint                     | Description                      |
|--------|-------------------------------|----------------------------------|
| POST   | `/api/v1/token/refresh`       | Refresh JWT access token         |

### Email Verification & Password Reset

| Method | Endpoint                       | Description                          |
|--------|---------------------------------|--------------------------------------|
| POST   | `/api/v1/user/verify-email`     | Verify user email                    |
| POST   | `/api/v1/user/forgot-password`  | Request password reset link          |
| POST   | `/api/v1/user/reset-password`   | Reset the user password              |
