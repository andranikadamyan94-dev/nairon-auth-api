-- Fix FK constraints to add ON UPDATE CASCADE (Prisma default).
-- Original inline FKs were created without ON UPDATE, defaulting to NO ACTION.

ALTER TABLE "UserRole" DROP CONSTRAINT IF EXISTS "UserRole_userId_fkey";
ALTER TABLE "UserRole" DROP CONSTRAINT IF EXISTS "UserRole_roleId_fkey";

DO $$ BEGIN
    ALTER TABLE "UserRole" ADD CONSTRAINT "UserRole_userId_fkey"
        FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE "UserRole" ADD CONSTRAINT "UserRole_roleId_fkey"
        FOREIGN KEY ("roleId") REFERENCES "Role"("id") ON DELETE CASCADE ON UPDATE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

ALTER TABLE "RolePermission" DROP CONSTRAINT IF EXISTS "RolePermission_roleId_fkey";
ALTER TABLE "RolePermission" DROP CONSTRAINT IF EXISTS "RolePermission_permissionId_fkey";

DO $$ BEGIN
    ALTER TABLE "RolePermission" ADD CONSTRAINT "RolePermission_roleId_fkey"
        FOREIGN KEY ("roleId") REFERENCES "Role"("id") ON DELETE CASCADE ON UPDATE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE "RolePermission" ADD CONSTRAINT "RolePermission_permissionId_fkey"
        FOREIGN KEY ("permissionId") REFERENCES "Permission"("id") ON DELETE CASCADE ON UPDATE CASCADE;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
