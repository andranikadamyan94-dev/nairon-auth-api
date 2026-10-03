-- Read-only super administrator (2026-10-03): a second super-admin role whose
-- holders see everything but may change nothing. The flag lives beside
-- isSuperAdmin so every reader of the users DB can tell the two apart.
ALTER TABLE "Role" ADD COLUMN IF NOT EXISTS "readOnly" BOOLEAN NOT NULL DEFAULT false;

-- Seed the role once. Like the existing super-admin role it is never created
-- through the API; its level copies the sitting super-admin role's (0 on
-- every environment so far) so it sorts beside it.
INSERT INTO "Role" ("name", "level", "isSuperAdmin", "readOnly")
SELECT 'Read-Only Super Admin',
       COALESCE((SELECT MIN("level") FROM "Role" WHERE "isSuperAdmin" = true), 0),
       true,
       true
WHERE NOT EXISTS (SELECT 1 FROM "Role" WHERE "readOnly" = true);
