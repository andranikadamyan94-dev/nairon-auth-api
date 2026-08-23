-- Per-entity grants go live: a RolePermission row now only applies in its own
-- entity (0 = everywhere). Rows written at concrete entityIds are leftovers of
-- an old model that was later ignored entirely — since then the resolver
-- unioned them, so they have been acting as global grants. Enforcing them
-- as-is would silently strip access: 5 roles on staging carry 150 permissions
-- that exist ONLY at some entity (a finance lead would lose 73 permissions the
-- moment they switched entity).
--
-- So: promote every entity-only grant to the base set, then drop all non-zero
-- rows (redundant once the base covers them). Effective access is unchanged;
-- deliberate per-entity extras start fresh from the grants UI.

INSERT INTO "RolePermission" ("roleId", "permissionId", "entityId")
SELECT DISTINCT rp."roleId", rp."permissionId", 0
FROM "RolePermission" rp
WHERE rp."entityId" <> 0
  AND NOT EXISTS (
    SELECT 1 FROM "RolePermission" b
    WHERE b."roleId" = rp."roleId"
      AND b."permissionId" = rp."permissionId"
      AND b."entityId" = 0
  )
ON CONFLICT DO NOTHING;

DELETE FROM "RolePermission" WHERE "entityId" <> 0;
