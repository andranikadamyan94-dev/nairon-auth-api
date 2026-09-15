-- #2200 Outsource user (2026-09-15): external contractors are flagged on the
-- user record. Roles and permissions govern their access as for anyone else;
-- the flag only excludes them from the CRM performance and bonus calculations.
ALTER TABLE "User" ADD COLUMN IF NOT EXISTS "isOutsource" BOOLEAN NOT NULL DEFAULT false;
