import { Injectable, OnModuleInit } from '@nestjs/common';
import { AuthPrismaService } from '../prisma.service';

export const ALL_PERMISSIONS = [
  'create_task', 'update_task', 'delete_task', 'assign_task_to_user', 'assign_task_to_role',
  'complete_task', 'comment_task', 'view_task', 'track_performance', 'view_all_tasks',
  'create_department', 'update_department', 'delete_department', 'view_department',
  'view_all_departments', 'assign_department_to_user', 'remove_user_from_department',
  'create_role', 'update_role', 'delete_role', 'view_role', 'view_department_roles', 'view_all_roles',
  'assign_permissions', 'view_permissions', 'view_all_permissions',
  'create_user', 'update_user', 'password_request', 'password_change', 'delete_user',
  'view_user', 'view_user_permissions', 'assign_roles', 'view_all_users', 'set_otp', 'view_bonus_reports',
  'log_policy', 'update_policy_log', 'delete_policy_log', 'view_policy_log', 'view_all_policy_logs',
  'create_policy', 'update_policy', 'delete_policy', 'view_policy', 'view_all_policies',
  'view_transfers_chart', 'create_transfer', 'update_transfer', 'delete_transfer',
  'view_transfer', 'view_all_transfers',
  'create_transfer_nature', 'update_transfer_nature', 'delete_transfer_nature',
  'view_transfer_nature', 'view_all_transfer_natures',
  'create_transfer_category', 'update_transfer_category', 'delete_transfer_category',
  'view_transfer_category', 'view_all_transfer_categories',
  'create_transfer_department', 'update_transfer_department', 'delete_transfer_department',
  'view_transfer_department', 'view_all_transfer_departments',
  'page_financial', 'page_policies', 'page_members', 'page_tasks', 'page_applications',
  'page_assignments', 'page_warehouse',
  'create_project', 'update_project', 'delete_project', 'manage_project_members',
  'create_project_task', 'update_project_task', 'delete_project_task', 'assign_project_task',
  'comment_project_task', 'manage_project_attachments', 'manage_project_subtasks',
  'manage_project_labels', 'manage_project_tags',
  'create_sprint', 'update_sprint', 'delete_sprint', 'manage_sprint_status',
  'create_project_status', 'update_project_status', 'delete_project_status',
  'manage_backlogs',
  'view_warehouse',
  'finance_approval', 'director_approval',
  'view_system_users',
];

@Injectable()
export class PermissionsService implements OnModuleInit {
  constructor(private prisma: AuthPrismaService) {}

  async onModuleInit() {
    await this.seedPermissions();
    setInterval(() => {
      this.prisma.$queryRaw`SELECT 1`.catch(() => {});
    }, 4 * 60 * 1000);
  }

  async seedPermissions() {
    await Promise.all(
      ALL_PERMISSIONS.map((name) =>
        this.prisma.permission.upsert({ where: { name }, create: { name }, update: {} }),
      ),
    );
  }

  async getAllPermissions() {
    return this.prisma.permission.findMany({ orderBy: { name: 'asc' } });
  }
}