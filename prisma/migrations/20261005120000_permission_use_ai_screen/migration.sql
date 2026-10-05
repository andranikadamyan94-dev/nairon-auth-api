-- Screen agent (2026-10-05): the permission `use_ai_screen` — the assistant may
-- do a task through the screen for this person (a browser signed in as them,
-- every change paused for their confirmation).
--
-- Catalogue row only, the same row PermissionsService.seedPermissions upserts
-- at start-up; it is here so the row exists before the new auth-api first
-- starts. It is granted to NO role: the owner grants it per role (locally:
-- claude-work/ops-local/grant-use-ai-screen.sql). Idempotent.
INSERT INTO "Permission" ("name")
VALUES ('use_ai_screen')
ON CONFLICT ("name") DO NOTHING;
