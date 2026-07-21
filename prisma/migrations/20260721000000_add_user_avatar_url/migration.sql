-- Add a first-class avatar URL to User so every directory/list endpoint can
-- surface profile pictures for any user (not just the logged-in one).
ALTER TABLE "User" ADD COLUMN IF NOT EXISTS "avatarUrl" TEXT;
