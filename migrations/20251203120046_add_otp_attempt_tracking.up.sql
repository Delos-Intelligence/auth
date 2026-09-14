-- Add OTP brute force protection columns to one_time_tokens table

ALTER TABLE {{ index .Options "Namespace" }}.one_time_tokens
ADD COLUMN IF NOT EXISTS attempt_count INT DEFAULT 0,
ADD COLUMN IF NOT EXISTS invalidated_at timestamptz NULL;

-- Add index for invalidated tokens
CREATE INDEX IF NOT EXISTS one_time_tokens_invalidated_at_idx
ON {{ index .Options "Namespace" }}.one_time_tokens(invalidated_at)
WHERE invalidated_at IS NOT NULL;
