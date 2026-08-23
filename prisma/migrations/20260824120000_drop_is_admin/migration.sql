-- The isAdmin flag is gone: level-0 roles are the only admin concept, scoped
-- by their UserRole.entityId (0 = every entity). Flag-holders lose admin with
-- the column — by design, nothing is migrated onto roles here.
ALTER TABLE "User" DROP COLUMN IF EXISTS "isAdmin";
