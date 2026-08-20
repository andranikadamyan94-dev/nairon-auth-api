-- The policies feature is gone (page, API modules and nav removed): its
-- permissions guard nothing. Deleting the rows cascades their grants.
DELETE FROM "Permission" WHERE "name" IN (
  'create_policy','update_policy','delete_policy','view_policy','view_all_policies','page_policies',
  'log_policy','update_policy_log','delete_policy_log','view_policy_log','view_all_policy_logs'
);
