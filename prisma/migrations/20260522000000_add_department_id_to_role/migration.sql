-- Add departmentId to Role (nullable, no FK since departments live in nairon_hr)
ALTER TABLE "Role" ADD COLUMN IF NOT EXISTS "departmentId" INTEGER;
