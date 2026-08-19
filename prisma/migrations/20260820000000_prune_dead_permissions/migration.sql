-- Permissions that no code has ever checked: the flat "task" family from a
-- module superseded by project tasks, plus one-off leftovers. Grantable
-- no-ops until now; removing the rows cascades their RolePermission grants,
-- none of which ever did anything.
DELETE FROM "Permission" WHERE "name" IN (
  'create_task','update_task','delete_task','assign_task_to_user',
  'assign_task_to_role','complete_task','comment_task','view_task',
  'track_performance','view_all_tasks','page_tasks','password_change',
  'view_permissions','page_financial','view_system_users','delete_advance'
);
