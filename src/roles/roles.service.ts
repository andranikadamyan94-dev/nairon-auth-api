import { Injectable, NotFoundException } from '@nestjs/common';
import { AuthPrismaService } from '../prisma.service';
import { M } from '../constants/messages';

@Injectable()
export class RolesService {
  constructor(private prisma: AuthPrismaService) {}

  async createRole(name: string, level: number, departmentId?: number) {
    return this.prisma.role.create({ data: { name, level, departmentId } });
  }

  async getAllRoles(departmentId?: number) {
    return this.prisma.role.findMany({
      where: departmentId ? { departmentId } : undefined,
      include: { permissions: { include: { permission: true } } },
      orderBy: { level: 'asc' },
    });
  }

  async getRoleById(id: number, entityId?: number) {
    let permissionsWhere: any = undefined;
    if (entityId !== undefined && entityId > 0) {
      const entityConfigured = await this.prisma.rolePermission.findFirst({
        where: { roleId: id, entityId, permission: { name: '_entity_configured_' } },
        include: { permission: true },
      });
      permissionsWhere = entityConfigured ? { entityId } : { entityId: 0 };
    } else if (entityId === 0) {
      permissionsWhere = { entityId: 0 };
    }
    const role = await this.prisma.role.findUnique({
      where: { id },
      include: { permissions: { where: permissionsWhere, include: { permission: true } } },
    });
    if (!role) throw new NotFoundException(M.role.notFound);
    return role;
  }

  async updateRole(id: number, data: { name?: string; level?: number; departmentId?: number | null }) {
    return this.prisma.role.update({ where: { id }, data });
  }

  async deleteRole(id: number) {
    return this.prisma.role.delete({ where: { id } });
  }

  async assignPermissionsToRole(roleId: number, permissionNames: string[], entityId = 0) {
    const allNames = entityId > 0
      ? [...new Set([...permissionNames, '_entity_configured_'])]
      : permissionNames;

    for (const name of allNames) {
      await this.prisma.permission.upsert({
        where: { name },
        create: { name },
        update: {},
      });
    }
    const permissions = await this.prisma.permission.findMany({
      where: { name: { in: allNames } },
    });
    await this.prisma.rolePermission.deleteMany({ where: { roleId, entityId } });
    if (permissions.length > 0) {
      await this.prisma.rolePermission.createMany({
        data: permissions.map((p) => ({ roleId, permissionId: p.id, entityId })),
      });
    }
    return { success: true };
  }

  async assignRolesToUser(userId: number, roleIds: number[], entityId = 0) {
    await this.prisma.userRole.deleteMany({ where: { userId, entityId } });
    if (roleIds.length > 0) {
      await this.prisma.userRole.createMany({
        data: roleIds.map((roleId) => ({ userId, roleId, entityId })),
      });
    }
    return { success: true };
  }
}