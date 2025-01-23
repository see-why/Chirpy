-- +goose Up
CREATE TABLE chirps (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users ON DELETE CASCADE,
    body TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

-- +goose Down
DELETE FROM chirps;