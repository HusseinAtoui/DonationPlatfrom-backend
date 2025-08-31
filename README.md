# Donation Platform Backend

This is the backend for the Donation Platform application. It provides all the API endpoints and handles authentication, database interactions, and AWS integrations.

---

## Getting Started

### Prerequisites
- Node.js installed
- npm installed
- AWS credentials (if using S3 or other AWS services)

### Installation
1. Clone the repository:
   ```bash
   git clone <your-repo-url>
   cd donationplatform-backend
   ```
2. Install dependencies:
   ```bash
   npm install
   ```

### Running the Server
Start the server with:
```bash
node server.js
```
By default, it will run on `http://localhost:4000`.

---

## Project Structure

- **api/** – Contains all the endpoints for the routes (user, NGO, posts, requests, etc.).
- **middleware/** – Contains middleware for decoding JWT tokens and checking user roles.
- **server.js** – Entry point of the application; connects routes, middleware, and starts the server.

---

## Environment Variables

Create a `.env` file in the root directory with the following structure:

```
# AWS
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
AWS_REGION=eu-north-1
LOGOS_BUCKET=donationsimages
MESSAGES_BUCKET=ngo-donor-messages

# Email
EMAIL_PASS=your-email-password
EMAIL_RECEIVER=tyebetyebak@gmail.com

# DynamoDB / Tables
NGO_TABLE=NGOs
USER_TABLE=Donors
POSTS_TABLE=Posts
POSTS_PK=id
REQUESTS_TABLE=Requests
CONVERSATIONS_TABLE=conversation
MESSAGES_TABLE=messages

# JWT & API
JWT_SECRET=your-jwt-secret
API_URL=http://localhost:4000
FRONTEND_URL=http://localhost:3000

# Google OAuth
GOOGLE_CLIENT_SECRET1=your-google-client-secret
GOOGLE_CLIENT_ID1=your-google-client-id
```

---

## Notes
- Make sure your AWS credentials have the required permissions for S3 and DynamoDB operations.
- Ensure the `.env` file is added to `.gitignore` to avoid exposing sensitive information.
- Use JWT tokens to authenticate requests to protected routes.

---

## Quick Commands

- Install dependencies:
  ```bash
  npm install
  ```
- Start server:
  ```bash
  node server.js
  ```

