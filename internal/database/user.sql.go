// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.28.0
// source: user.sql

package database

import (
	"context"
)

const createUser = `-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email)
VALUES (
    gen_random_uuid(),
    NOW(),
    NOW(),
    $1
)
RETURNING id, email, created_at, updated_at
`

func (q *Queries) CreateUser(ctx context.Context, email string) (User, error) {
	row := q.db.QueryRowContext(ctx, createUser, email)
	var i User
	err := row.Scan(
		&i.ID,
		&i.Email,
		&i.CreatedAt,
		&i.UpdatedAt,
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

const selectUsers = `-- name: SelectUsers :many
SELECT id, email, created_at, updated_at FROM users
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
