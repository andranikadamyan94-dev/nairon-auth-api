import { Injectable, OnModuleInit } from '@nestjs/common';
import { AuthPrismaService } from '../prisma.service';

export const ALL_PERMISSIONS = [
      
      
  'create_department', 'update_department', 'delete_department', 'view_department',
  'view_all_departments', 'assign_department_to_user', 'remove_user_from_department',
  'create_role', 'update_role', 'delete_role', 'view_role', 'view_department_roles', 'view_all_roles',
  'assign_permissions',  'view_all_permissions',
  'create_user', 'update_user', 'password_request',  'delete_user',
  'view_user', 'view_user_permissions', 'assign_roles', 'view_all_users', 'set_otp', 'view_bonus_reports',
      
      
  'view_transfers_chart', 'create_transfer', 'update_transfer', 'delete_transfer',
  'view_transfer', 'view_all_transfers',
  'create_payroll_run', 'view_all_payroll_runs',
  'create_advance', 'update_advance',  'view_advance', 'view_all_advances',
  'create_transfer_nature', 'update_transfer_nature', 'delete_transfer_nature',
  'view_transfer_nature', 'view_all_transfer_natures',
  'create_transfer_category', 'update_transfer_category', 'delete_transfer_category',
  'view_transfer_category', 'view_all_transfer_categories',
  'create_transfer_department', 'update_transfer_department', 'delete_transfer_department',
  'view_transfer_department', 'view_all_transfer_departments',
  'create_entity', 'view_entity', 'update_entity', 'delete_entity',
   
   
  
  'page_finance',   'page_members',  'page_applications',
  'page_assignments', 'page_warehouse',
  'create_project', 'update_project', 'delete_project', 'manage_project_members',
  'create_project_task', 'update_project_task', 'delete_project_task', 'assign_project_task',
  'comment_project_task', 'manage_project_attachments', 'manage_project_subtasks',
  'manage_project_labels', 'manage_project_tags',
  'move_task_to_sprint', 'move_task_between_projects',
  // Report export button on the assignments board (crm-client gates on it).
  'generate_report',
  // See other people's private tasks (creators and assignees always see
  // their own). Super-admins and isAdmin bypass without the grant.
  'view_private_tasks',
  'create_sprint', 'update_sprint', 'delete_sprint', 'manage_sprint_status',
  'create_project_status', 'update_project_status', 'delete_project_status',
  'manage_backlogs',
  'invite_calendar_departments', 'view_team_calendar',
  'view_warehouse',
  'manage_warehouse',
  'manage_items', 'manage_categories',
  'manage_assets', 'manage_maintenance',
  'manage_inventory',
  'manage_procurement',
  'view_reservations', 'manage_reservations',
  'manage_resource_returns',
  'view_resources', 'view_assets', 'view_maintenance',
  'view_partners', 'manage_partners',
  'view_procurement', 'view_resource_returns',
  // Warehouse notification audiences. manage_warehouse holders receive all
  // warehouse alerts regardless; these opt in people who don't manage the
  // warehouse but need to know.
  'receive_stock_alerts', 'receive_procurement_alerts', 'receive_reservation_alerts',
  'view_responsibilities', 'manage_responsibilities',
  'finance_approval', 'director_approval', 'manage_recurring_transfers',
  
  'excuse_sprint_task',
  'manage_performance',
  'view_all_performance',
  'view_performance_trends',
  'send_notification',
  'manage_application_types',
  'submit_application',
  'view_all_applications',
  'approve_applications',
  'add_assign_acceptor',
  'manage_department_requests',
  'create_department_demand',
  // Learning platform
  'view_learning', 'author_courses', 'assign_courses', 'manage_learning', 'view_team_learning',
  // Peer feedback
  'give_feedback', 'moderate_feedback', 'view_team_feedback', 'manage_feedback_forms',
  // Disciplinary notices
  'issue_disciplinary_notice', 'view_disciplinary_notices',
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