-- name: CreateChirp :one
INSERT INTO chirps (id, user_id, created_at, updated_at, body)
VALUES (
    gen_random_uuid(),
    $1,
    NOW(),
    NOW(),
    $2
)
RETURNING *;
