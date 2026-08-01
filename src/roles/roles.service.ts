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

  // Entity is ignored for now: a role's permissions are role-level. Returns the
  // role with the union of its granted permissions across any entityId (the
  // `_entity_configured_` sentinel is filtered out), deduped by permission id.
  async getRoleById(id: number, _entityId?: number) {
    const role = await this.prisma.role.findUnique({
      where: { id },
      include: { permissions: { include: { permission: true } } },
    });
    if (!role) throw new NotFoundException(M.role.notFound);
    const seen = new Set<number>();
    const permissions = role.permissions.filter((rp) => {
      if (rp.permission?.name === '_entity_configured_') return false;
      if (seen.has(rp.permissionId)) return false;
      seen.add(rp.permissionId);
      return true;
    });
    return { ...role, permissions };
  }

  async updateRole(id: number, data: { name?: string; level?: number; departmentId?: number | null }) {
    return this.prisma.role.update({ where: { id }, data });
  }

  async deleteRole(id: number) {
    return this.prisma.role.delete({ where: { id } });
  }

  // Entity is ignored for now: permissions are assigned to the role directly.
  // The full set is written at entityId 0 and ALL of the role's previous rows
  // (any entityId, including legacy per-entity grants + sentinels) are cleared,
  // so unchecking a permission actually removes it everywhere.
  async assignPermissionsToRole(roleId: number, permissionNames: string[], _entityId = 0) {
    const names = [...new Set(permissionNames)].filter((n) => n !== '_entity_configured_');
    for (const name of names) {
      await this.prisma.permission.upsert({ where: { name }, create: { name }, update: {} });
    }
    const permissions = names.length
      ? await this.prisma.permission.findMany({ where: { name: { in: names } } })
      : [];
    await this.prisma.rolePermission.deleteMany({ where: { roleId } });
    if (permissions.length > 0) {
      await this.prisma.rolePermission.createMany({
        data: permissions.map((p) => ({ roleId, permissionId: p.id, entityId: 0 })),
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