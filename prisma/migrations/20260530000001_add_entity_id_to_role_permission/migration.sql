ALTER TABLE "RolePermission" ADD COLUMN IF NOT EXISTS "entityId" INTEGER NOT NULL DEFAULT 0;
ALTER TABLE "RolePermission" DROP CONSTRAINT "RolePermission_pkey";
ALTER TABLE "RolePermission" ADD CONSTRAINT "RolePermission_pkey" PRIMARY KEY ("roleId", "permissionId", "entityId");
