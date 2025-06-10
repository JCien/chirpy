-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email)
Values (
  gen_random_uuid(),
  NOW(),
  NOW(),
  $1
  )
RETURNING *;

-- name: ResetUsers :exec
DELETE FROM users;

-- name: AddPassword :one
UPDATE users
SET hashed_password = $1
WHERE id = $2
RETURNING *;

-- name: GetUserByEmail :one
SELECT * FROM users
WHERE email = $1;
