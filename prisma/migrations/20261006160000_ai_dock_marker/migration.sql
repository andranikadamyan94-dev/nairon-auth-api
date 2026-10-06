-- AI dock marker (owner, 2026-10-06): the dock's «Նշել էջում» — the person marks a
-- region or an element of the page they are on, and it travels with their next
-- message (ai-api AI_MARKER_SELECTION; design/MARKER-SELECTION-CONTRACT.md).
--
--   ai_dock_marker     marker button in the composer
--
-- A per-role switch like the nine of 20261006120000_ai_dock_permissions, and like
-- them it only narrows: use_ai_assistant is still required. Nothing changes for
-- anybody: every role that holds use_ai_assistant gets it, in each organisation
-- it holds use_ai_assistant in (same "entityId"; 0 = everywhere). It is NOT one
-- of the nine the session's aiDockPermissions marker counts, so an auth-api
-- without this row still reads the nine literally. Idempotent.

INSERT INTO "Permission" ("name") VALUES
  ('ai_dock_marker')
ON CONFLICT ("name") DO NOTHING;

INSERT INTO "RolePermission" ("roleId", "permissionId", "entityId")
SELECT rp."roleId", marker.id, rp."entityId"
FROM "RolePermission" rp
JOIN "Permission" assistant ON assistant.id = rp."permissionId" AND assistant.name = 'use_ai_assistant'
CROSS JOIN (SELECT id FROM "Permission" WHERE name = 'ai_dock_marker') marker
ON CONFLICT ("roleId", "permissionId", "entityId") DO NOTHING;
