-- AI dock controls (owner, 2026-10-06): every control in the AI dock is a role
-- permission an admin switches on or off per role, the two modes included.
--
--   ai_mode_auto       «Ավտոմատ» mode
--   ai_mode_screen     «Էկրանով» mode (either it or use_ai_screen grants the screen)
--   ai_dock_saved      bookmark «Հիշողություն» (memory panel)
--   ai_dock_history    clock «Իմ հանձնարարությունները» (long goals panel)
--   ai_dock_export     tray «Հաստատման սպասող գործընթացներ» (workflow approvals)
--   ai_dock_workflows  «Գործընթացներ» (workflows page)
--   ai_dock_new_chat   «Նոր զրույց»
--   ai_dock_attach     paperclip: attach, drop or paste a file
--   ai_dock_voice      microphone: Live voice, wake word, «Շարունակել ձայնով»
--
-- Each only narrows: the feature's own right (the assistant, voice, memory,
-- goals, workflows and screen rights) is still required.
--
-- Nothing changes for anybody: every role that holds use_ai_assistant gets all
-- of them except ai_mode_screen, in each organisation it holds use_ai_assistant
-- in (same "entityId"; 0 = everywhere). ai_mode_screen follows today's
-- use_ai_screen grants exactly — granting it wider would open the screen agent
-- to roles that do not have it. Idempotent.

INSERT INTO "Permission" ("name") VALUES
  ('ai_mode_auto'),
  ('ai_mode_screen'),
  ('ai_dock_saved'),
  ('ai_dock_history'),
  ('ai_dock_export'),
  ('ai_dock_workflows'),
  ('ai_dock_new_chat'),
  ('ai_dock_attach'),
  ('ai_dock_voice')
ON CONFLICT ("name") DO NOTHING;

INSERT INTO "RolePermission" ("roleId", "permissionId", "entityId")
SELECT rp."roleId", dock.id, rp."entityId"
FROM "RolePermission" rp
JOIN "Permission" assistant ON assistant.id = rp."permissionId" AND assistant.name = 'use_ai_assistant'
CROSS JOIN (
  SELECT id FROM "Permission"
  WHERE name IN ('ai_mode_auto', 'ai_dock_saved', 'ai_dock_history', 'ai_dock_export',
                 'ai_dock_workflows', 'ai_dock_new_chat', 'ai_dock_attach', 'ai_dock_voice')
) dock
ON CONFLICT ("roleId", "permissionId", "entityId") DO NOTHING;

INSERT INTO "RolePermission" ("roleId", "permissionId", "entityId")
SELECT rp."roleId", mode_screen.id, rp."entityId"
FROM "RolePermission" rp
JOIN "Permission" screen ON screen.id = rp."permissionId" AND screen.name = 'use_ai_screen'
CROSS JOIN (SELECT id FROM "Permission" WHERE name = 'ai_mode_screen') mode_screen
ON CONFLICT ("roleId", "permissionId", "entityId") DO NOTHING;
