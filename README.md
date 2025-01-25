# Chirpy

A modern social media API service built with Go that enables users to share short messages.

## Features
- JWT-based authentication
- User management (register/login)
- Message posting and retrieval
- Content moderation
- Request metrics
- PostgreSQL database

## Quick Start
### Clone repository
git clone https://github.com/see-why/chirpy.git

### Install dependencies
go mod download

### Setup environment
cp .env.example .env

### Edit .env with your settings

###  Run migrations
goose -dir sql/schema postgres "postgres://user:pass@localhost:5432/chirpy?sslmode=disable" up

###  Start server
go run main.go

## API Endpoints
### Auth
- POST /api/users - Register
- POST /api/login - Login
- POST /api/refresh - Refresh token
- POST /api/revoke - Revoke token
### Chirps
- GET /api/chirps - List chirps
- GET /api/chirps/{id} - Get chirp
- POST /api/chirps - Create chirp
### Admin
- GET /admin/metrics - View metrics
- POST /admin/reset - Reset metrics (dev only)

## Environment Variables
- DB_URL="postgres://user:password@localhost:5432/chirpy?sslmode=disable"
- PLATFORM="dev"
- JWT_SECRET="your-secret-key"

## Development
### Database Migrations
Located in schema:

- 001_users.sql
- 002_chirps.sql
- 003_add_password_to_users.sql
- 004_refresh_tokens.sql

## Dependencies
- github.com/golang-jwt/jwt/v5
- github.com/google/uuid
- github.com/joho/godotenv
- github.com/lib/pq
- golang.org/x/crypto