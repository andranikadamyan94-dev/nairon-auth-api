import { BadRequestException, ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import { AuthPrismaService } from '../prisma.service';
import { M } from '../constants/messages';

@Injectable()
export class RolesService {
  constructor(private prisma: AuthPrismaService) {}

  /** Super-admin roles are managed at the database only — no API may edit,
   *  delete, re-grant or assign them, and no API can create one (the DTO
   *  carries no such field; this guard covers the id-addressed routes). */
  private async assertNotSuperAdminRole(id: number) {
    const role = await this.prisma.role.findUnique({ where: { id }, select: { isSuperAdmin: true } });
    if ((role as any)?.isSuperAdmin) {
      throw new BadRequestException(M.role.superAdminUntouchable);
    }
  }

  // Phase 6 decouple (2026-09-08): Role.departmentId is retired — never
  // written, never filtered on. The column stays until the legacy tables go.
  async createRole(name: string, level: number, _departmentId?: number) {
    return this.prisma.role.create({ data: { name, level } });
  }

  async getAllRoles(_departmentId?: number, includeSuperAdmin = false) {
    // Super-admin roles stay out of role lists — they are not part of the
    // grantable catalog — unless HR asks for them on behalf of a super-admin
    // filling the member form (2026-09-16: super-admins assign the role to
    // each other from there).
    return this.prisma.role.findMany({
      where: includeSuperAdmin ? {} : ({ isSuperAdmin: false } as any),
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
    await this.assertNotSuperAdminRole(id);
    const { departmentId: _retired, ...rest } = data;
    return this.prisma.role.update({ where: { id }, data: rest });
  }

  async deleteRole(id: number) {
    await this.assertNotSuperAdminRole(id);
    return this.prisma.role.delete({ where: { id } });
  }

  /**
   * Replaces ONE entity's grant set for the role: entityId 0 replaces the
   * base (everywhere) set, a concrete entityId replaces only that entity's
   * extras. Other entities' rows are untouched, so configuring one entity
   * can never wipe another's. Also drops legacy sentinel rows for that scope.
   */
  /** Assignment endpoints refuse super-admin roles wholesale. */
  private async assertNoSuperAdminRoles(roleIds: number[]) {
    if (!roleIds.length) return;
    const hit = await this.prisma.role.findFirst({
      where: { id: { in: roleIds }, isSuperAdmin: true } as any,
      select: { id: true },
    });
    if (hit) throw new BadRequestException(M.role.superAdminUntouchable);
  }

  async assignPermissionsToRole(roleId: number, permissionNames: string[], entityId = 0) {
    await this.assertNotSuperAdminRole(roleId);
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
    await this.assertNoSuperAdminRoles(roleIds);
    // Existing super-admin assignments survive the replace: they are not
    // manageable from here in either direction.
    await this.prisma.userRole.deleteMany({
      where: { userId, entityId, role: { isSuperAdmin: false } as any },
    });
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
    opts: { manageSuperAdmin?: boolean; actorId?: number } = {},
  ) {
    const rows = assignments.flatMap((a) =>
      [...new Set(a.roleIds ?? [])].map((roleId) => ({
        userId,
        roleId,
        entityId: a.entityId ?? 0,
      })),
    );
    if (!opts.manageSuperAdmin) {
      await this.assertNoSuperAdminRoles(rows.map((r) => r.roleId));
      await this.prisma.$transaction([
        // The full-map replace never touches super-admin assignments either.
        this.prisma.userRole.deleteMany({ where: { userId, role: { isSuperAdmin: false } as any } }),
        ...(rows.length
          ? [this.prisma.userRole.createMany({ data: rows, skipDuplicates: true })]
          : []),
      ]);
      return { success: true };
    }

    // A super-admin is saving the form (HR authorized the change per entity):
    // the map is the whole truth, super-admin assignments included. Two
    // invariants stay with the data, whoever asks: nobody drops their own
    // super-admin role by accident, and the last active super-admin stays.
    const superRoleIds = new Set(
      (await this.prisma.role.findMany({ where: { isSuperAdmin: true } as any, select: { id: true } })).map((r) => r.id),
    );
    const current = await this.prisma.userRole.findMany({
      where: { userId, roleId: { in: [...superRoleIds] } },
      select: { roleId: true, entityId: true },
    });
    const keeps = (c: { roleId: number; entityId: number }) =>
      rows.some((r) => r.roleId === c.roleId && r.entityId === c.entityId);
    const dropsSuper = current.some((c) => !keeps(c));
    if (dropsSuper && opts.actorId === userId) {
      throw new BadRequestException(M.role.superAdminSelfRemoval);
    }
    if (dropsSuper && !rows.some((r) => superRoleIds.has(r.roleId))) {
      const others = await this.prisma.user.count({
        where: {
          id: { not: userId },
          deactivatedAt: null,
          roles: { some: { role: { isSuperAdmin: true } as any } },
        },
      });
      if (others === 0) throw new ConflictException(M.role.lastSuperAdmin);
    }
    await this.prisma.$transaction([
      this.prisma.userRole.deleteMany({ where: { userId } }),
      ...(rows.length
        ? [this.prisma.userRole.createMany({ data: rows, skipDuplicates: true })]
        : []),
    ]);
    return { success: true };
  }
}