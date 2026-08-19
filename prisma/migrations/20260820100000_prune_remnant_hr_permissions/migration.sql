-- Remnants of pre-Applications HR: attendance and leave-request management
-- never got UI or guards in the current app (leave lives inside Applications
-- post-actions now), and the work-schedule endpoint is self-service with no
-- managed target. Grantable no-ops — removing cascades their unused grants.
DELETE FROM "Permission" WHERE "name" IN (
  'manage_attendance','view_all_attendance',
  'manage_leave_requests','review_leave_requests',
  'manage_work_schedule'
);
