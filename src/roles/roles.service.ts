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

  /**
   * Grants are ADDITIVE per entity: rows at entityId 0 are the role's base
   * set (apply everywhere), rows at a concrete entityId are extras for that
   * entity only. Effective set in entity E = base ∪ E.
   *
   * Returns every row with its entityId so the grants UI can draw base and
   * per-entity extras separately; rows for the same permission at several
   * entities are all kept. The legacy `_entity_configured_` sentinel is
   * filtered out.
   */
  async getRoleById(id: number, _entityId?: number) {
    const role = await this.prisma.role.findUnique({
      where: { id },
      include: { permissions: { include: { permission: true } } },
    });
    if (!role) throw new NotFoundException(M.role.notFound);
    const permissions = role.permissions.filter(
      (rp) => rp.permission?.name !== '_entity_configured_',
    );
    return { ...role, permissions };
  }

  async updateRole(id: number, data: { name?: string; level?: number; departmentId?: number | null }) {
    return this.prisma.role.update({ where: { id }, data });
  }

  async deleteRole(id: number) {
    return this.prisma.role.delete({ where: { id } });
  }

  /**
   * Replaces ONE entity's grant set for the role: entityId 0 replaces the
   * base (everywhere) set, a concrete entityId replaces only that entity's
   * extras. Other entities' rows are untouched, so configuring one entity
   * can never wipe another's. Also drops legacy sentinel rows for that scope.
   */
  async assignPermissionsToRole(roleId: number, permissionNames: string[], entityId = 0) {
    const names = [...new Set(permissionNames)].filter((n) => n !== '_entity_configured_');
    for (const name of names) {
      await this.prisma.permission.upsert({ where: { name }, create: { name }, update: {} });
    }
    const permissions = names.length
      ? await this.prisma.permission.findMany({ where: { name: { in: names } } })
      : [];
    await this.prisma.rolePermission.deleteMany({ where: { roleId, entityId } });
    if (permissions.length > 0) {
      await this.prisma.rolePermission.createMany({
        data: permissions.map((p) => ({ roleId, permissionId: p.id, entityId })),
        skipDuplicates: true,
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

  /**
   * Replace the user's COMPLETE role map in one shot: the payload states every
   * assignment the user should have, per entity (entityId 0 = every entity),
   * and anything not in it is removed. This is what the member form saves —
   * the per-entity variant of assignRolesToUser, which only replaces one
   * entity's set at a time.
   */
  async assignRoleMapToUser(
    userId: number,
    assignments: { entityId?: number; roleIds: number[] }[],
  ) {
    const rows = assignments.flatMap((a) =>
      [...new Set(a.roleIds ?? [])].map((roleId) => ({
        userId,
        roleId,
        entityId: a.entityId ?? 0,
      })),
    );
    await this.prisma.$transaction([
      this.prisma.userRole.deleteMany({ where: { userId } }),
      ...(rows.length
        ? [this.prisma.userRole.createMany({ data: rows, skipDuplicates: true })]
        : []),
    ]);
    return { success: true };
  }
}