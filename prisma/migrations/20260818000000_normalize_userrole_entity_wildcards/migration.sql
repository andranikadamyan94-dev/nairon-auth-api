-- Entity-scoped authorization goes live: an assignment's entityId now decides
-- where it applies (0 = every entity). Until today entityId was ignored, so
-- rows written with a concrete entityId were never *meant* as scoping — but
-- under the new resolution they would strip access whenever the client is in
-- a different entity. Collapse them to wildcards; deliberate scoping starts
-- fresh from the assignment UI.

-- Promote one non-zero row per (user, role) to the wildcard when none exists.
UPDATE "UserRole" ur
SET "entityId" = 0
WHERE ur."entityId" <> 0
  AND NOT EXISTS (
    SELECT 1 FROM "UserRole" x
    WHERE x."userId" = ur."userId" AND x."roleId" = ur."roleId" AND x."entityId" = 0
  )
  AND ur."entityId" = (
    SELECT MIN(y."entityId") FROM "UserRole" y
    WHERE y."userId" = ur."userId" AND y."roleId" = ur."roleId" AND y."entityId" <> 0
  );

-- Remaining non-zero rows are duplicates of a wildcard now.
DELETE FROM "UserRole" WHERE "entityId" <> 0;
