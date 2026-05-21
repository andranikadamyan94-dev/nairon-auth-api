import { Injectable, NotFoundException } from '@nestjs/common';
import { AuthPrismaService } from '../prisma.service';

@Injectable()
export class RolesService {
  constructor(private prisma: AuthPrismaService) {}

  async createRole(name: string, level: number) {
    return this.prisma.role.create({ data: { name, level } });
  }

  async getAllRoles() {
    return this.prisma.role.findMany({
      include: { permissions: { include: { permission: true } } },
      orderBy: { level: 'asc' },
    });
  }

  async getRoleById(id: number) {
    const role = await this.prisma.role.findUnique({
      where: { id },
      include: { permissions: { include: { permission: true } } },
    });
    if (!role) throw new NotFoundException('Role not found');
    return role;
  }

  async updateRole(id: number, name: string, level: number) {
    return this.prisma.role.update({ where: { id }, data: { name, level } });
  }

  async deleteRole(id: number) {
    return this.prisma.role.delete({ where: { id } });
  }

  async assignPermissionsToRole(roleId: number, permissionNames: string[]) {
    const permissions = await this.prisma.permission.findMany({
      where: { name: { in: permissionNames } },
    });
    await this.prisma.rolePermission.deleteMany({ where: { roleId } });
    if (permissions.length > 0) {
      await this.prisma.rolePermission.createMany({
        data: permissions.map((p) => ({ roleId, permissionId: p.id })),
      });
    }
    return { success: true };
  }

  async assignRolesToUser(userId: number, roleIds: number[]) {
    await this.prisma.userRole.deleteMany({ where: { userId } });
    if (roleIds.length > 0) {
      await this.prisma.userRole.createMany({
        data: roleIds.map((roleId) => ({ userId, roleId })),
      });
    }
    return { success: true };
  }
}