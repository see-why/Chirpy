// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.28.0
// source: user.sql

package database

import (
	"context"

	"github.com/google/uuid"
)

const createUser = `-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (
    gen_random_uuid(),
    NOW(),
    NOW(),
    $1,
    $2
)
RETURNING id, email, created_at, updated_at, hashed_password, is_chirpy_red
`

type CreateUserParams struct {
	Email          string
	HashedPassword string
}

func (q *Queries) CreateUser(ctx context.Context, arg CreateUserParams) (User, error) {
	row := q.db.QueryRowContext(ctx, createUser, arg.Email, arg.HashedPassword)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Email,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.HashedPassword,
		&i.IsChirpyRed,
	)
	return i, err
}

const deleteUser = `-- name: DeleteUser :exec
DELETE FROM users
`

func (q *Queries) DeleteUser(ctx context.Context) error {
	_, err := q.db.ExecContext(ctx, deleteUser)
	return err
}

const getUserByEmail = `-- name: GetUserByEmail :one
SELECT id, email, created_at, updated_at, hashed_password, is_chirpy_red FROM users WHERE email = $1
`

func (q *Queries) GetUserByEmail(ctx context.Context, email string) (User, error) {
	row := q.db.QueryRowContext(ctx, getUserByEmail, email)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Email,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.HashedPassword,
		&i.IsChirpyRed,
	)
	return i, err
}

const selectUsers = `-- name: SelectUsers :many
SELECT id, email, created_at, updated_at, hashed_password, is_chirpy_red FROM users
`

func (q *Queries) SelectUsers(ctx context.Context) ([]User, error) {
	rows, err := q.db.QueryContext(ctx, selectUsers)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []User
	for rows.Next() {
		var i User
		if err := rows.Scan(
			&i.ID,
			&i.Email,
			&i.CreatedAt,
			&i.UpdatedAt,
			&i.HashedPassword,
			&i.IsChirpyRed,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const updateUser = `-- name: UpdateUser :one
UPDATE users
SET email = $1,
    hashed_password = $2,
    updated_at = NOW()
WHERE id = $3
RETURNING id, email, created_at, updated_at, hashed_password, is_chirpy_red
`

type UpdateUserParams struct {
	Email          string
	HashedPassword string
	ID             uuid.UUID
}

func (q *Queries) UpdateUser(ctx context.Context, arg UpdateUserParams) (User, error) {
	row := q.db.QueryRowContext(ctx, updateUser, arg.Email, arg.HashedPassword, arg.ID)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Email,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.HashedPassword,
		&i.IsChirpyRed,
	)
	return i, err
}

const updateUserIsChirpyRed = `-- name: UpdateUserIsChirpyRed :one
UPDATE users
SET is_chirpy_red = $1
WHERE id = $2
RETURNING id, email, created_at, updated_at, hashed_password, is_chirpy_red
`

type UpdateUserIsChirpyRedParams struct {
	IsChirpyRed bool
	ID          uuid.UUID
}

func (q *Queries) UpdateUserIsChirpyRed(ctx context.Context, arg UpdateUserIsChirpyRedParams) (User, error) {
	row := q.db.QueryRowContext(ctx, updateUserIsChirpyRed, arg.IsChirpyRed, arg.ID)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Email,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.HashedPassword,
		&i.IsChirpyRed,
	)
	return i, err
}
