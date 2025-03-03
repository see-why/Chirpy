// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.28.0
// source: refresh_tokens.sql

package database

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
)

const createRefreshToken = `-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (id, user_id, token, revoked_at, expires_at, created_at, updated_at)
VALUES (
    gen_random_uuid(),
    $1,
    $2,
    $3,
    $4,
    NOW(),
    NOW()
)
RETURNING id, user_id, token, created_at, updated_at, expires_at, revoked_at
`

type CreateRefreshTokenParams struct {
	UserID    uuid.NullUUID
	Token     string
	RevokedAt sql.NullTime
	ExpiresAt time.Time
}

func (q *Queries) CreateRefreshToken(ctx context.Context, arg CreateRefreshTokenParams) (RefreshToken, error) {
	row := q.db.QueryRowContext(ctx, createRefreshToken,
		arg.UserID,
		arg.Token,
		arg.RevokedAt,
		arg.ExpiresAt,
	)
	var i RefreshToken
	err := row.Scan(
		&i.ID,
		&i.UserID,
		&i.Token,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.ExpiresAt,
		&i.RevokedAt,
	)
	return i, err
}

const getAccessTokenFromRefreshToken = `-- name: GetAccessTokenFromRefreshToken :one
SELECT id, user_id, token, revoked_at, expires_at, created_at, updated_at
FROM refresh_tokens
WHERE token = $1 AND revoked_at IS NULL AND expires_at > NOW()
`

type GetAccessTokenFromRefreshTokenRow struct {
	ID        uuid.UUID
	UserID    uuid.NullUUID
	Token     string
	RevokedAt sql.NullTime
	ExpiresAt time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (q *Queries) GetAccessTokenFromRefreshToken(ctx context.Context, token string) (GetAccessTokenFromRefreshTokenRow, error) {
	row := q.db.QueryRowContext(ctx, getAccessTokenFromRefreshToken, token)
	var i GetAccessTokenFromRefreshTokenRow
	err := row.Scan(
		&i.ID,
		&i.UserID,
		&i.Token,
		&i.RevokedAt,
		&i.ExpiresAt,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const revokeRefreshToken = `-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens
SET revoked_at = NOW(), updated_at = NOW()
WHERE token = $1
`

func (q *Queries) RevokeRefreshToken(ctx context.Context, token string) error {
	_, err := q.db.ExecContext(ctx, revokeRefreshToken, token)
	return err
}
