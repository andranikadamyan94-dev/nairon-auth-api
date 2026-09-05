-- Org restructure phase 1: super-admin becomes a flag off the seniority
-- ladder. Existing level-0 roles carry the authority over; level keeps its
-- number but stops meaning anything special.
ALTER TABLE "Role" ADD COLUMN IF NOT EXISTS "isSuperAdmin" BOOLEAN NOT NULL DEFAULT false;
UPDATE "Role" SET "isSuperAdmin" = true WHERE "level" = 0 AND "isSuperAdmin" = false;
