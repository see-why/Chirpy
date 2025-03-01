-- name: CreateRefreshToken :one
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
RETURNING *;

-- name: GetAccessTokenFromRefreshToken :one
SELECT id, user_id, token, revoked_at, expires_at, created_at, updated_at
FROM refresh_tokens
WHERE token = $1 AND revoked_at IS NULL AND expires_at > NOW();

-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens
SET revoked_at = NOW(), updated_at = NOW()
WHERE token = $1;
