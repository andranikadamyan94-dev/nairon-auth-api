-- Role.name was globally unique, but a role name is only meaningful within a
-- department — the same "Manager" is expected in several. The UI offers a
-- multi-department create and all but the first were rejected silently.
--
-- Idempotent: both statements are guarded, so re-running is a no-op.
--
-- Note: departmentId is nullable and Postgres treats NULLs as distinct, so this
-- index does not constrain roles that belong to no department.

-- Dropped both ways on purpose: a fresh replay of the migrations creates
-- Role_name_key as a table constraint (DROP INDEX cannot remove it), while
-- databases that were baselined carry it as a plain index.
ALTER TABLE "Role" DROP CONSTRAINT IF EXISTS "Role_name_key";
DROP INDEX IF EXISTS "Role_name_key";

CREATE UNIQUE INDEX IF NOT EXISTS "Role_name_departmentId_key"
  ON "Role" ("name", "departmentId");
