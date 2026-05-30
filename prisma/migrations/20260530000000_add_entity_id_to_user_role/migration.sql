-- Add entityId to UserRole with default 0 (global)
ALTER TABLE "UserRole" ADD COLUMN IF NOT EXISTS "entityId" INTEGER NOT NULL DEFAULT 0;

-- Update existing rows to have entityId = 0 (global)
UPDATE "UserRole" SET "entityId" = 0 WHERE "entityId" IS NULL;

-- Drop old primary key
ALTER TABLE "UserRole" DROP CONSTRAINT "UserRole_pkey";

-- Add new composite primary key including entityId
ALTER TABLE "UserRole" ADD CONSTRAINT "UserRole_pkey" PRIMARY KEY ("userId", "roleId", "entityId");
