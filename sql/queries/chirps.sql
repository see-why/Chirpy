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

-- name: SelectChirps :many
SELECT * FROM chirps;

-- name: SelectChirp :one
SELECT * FROM chirps WHERE id = $1;

-- name: DeleteChirp :exec
DELETE FROM chirps WHERE id = $1;

-- name: SelectChirpsByUserId :many
SELECT * FROM chirps WHERE user_id = $1;