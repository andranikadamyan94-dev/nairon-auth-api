-- Deactivation replaces deletion for offboarding.
--
-- Deleting a user dropped the row here and cascaded UserRole, but the other four
-- databases reference users by loose Int with no foreign keys, so attendance,
-- payroll, leave, tasks and assets were all silently orphaned. Keeping the row
-- and marking it deactivated preserves every one of those references.
ALTER TABLE "User" ADD COLUMN IF NOT EXISTS "deactivatedAt" TIMESTAMP(3);

-- Lists filter on this on every request, so it is worth an index even though
-- the table is small.
CREATE INDEX IF NOT EXISTS "User_deactivatedAt_idx" ON "User"("deactivatedAt");
