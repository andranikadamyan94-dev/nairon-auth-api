-- A position's seniority level is optional (2026-10-05): HR may create a
-- Հաստիք without picking an Աստիճան. Existing rows keep their level.
ALTER TABLE "Role" ALTER COLUMN "level" DROP NOT NULL;
