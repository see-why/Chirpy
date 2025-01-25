-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (
    gen_random_uuid(),
    NOW(),
    NOW(),
    $1,
    $2
)
RETURNING *;

-- name: DeleteUser :exec
DELETE FROM users;

-- name: SelectUsers :many
SELECT * FROM users;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1;
