import { BadRequestException } from '@nestjs/common';
import { M } from '../../constants/messages';
import { RolesService } from '../roles.service';

/*
 * #56 (2026-10-07): a role anyone holds is not deleted — the assignments would
 * cascade away and people would silently lose their rights. Super-admin roles
 * stay untouchable as before.
 */
function build(roles: { id: number; isSuperAdmin: boolean }[], userRoles: { roleId: number; userId: number }[]) {
  const deleted: number[] = [];
  const count = jest.fn(async ({ where }: any) => {
    const ids = userRoles.filter((ur) => ur.roleId === where.roleId).map((ur) => ur.userId);
    return [...new Set(ids)].map((userId) => ({ userId }));
  });
  const prisma: any = {
    role: {
      findUnique: async ({ where }: any) => roles.find((r) => r.id === where.id) ?? null,
      delete: async ({ where }: any) => {
        deleted.push(where.id);
        return { id: where.id };
      },
    },
    userRole: { findMany: count },
  };
  return { service: new RolesService(prisma), deleted, count };
}

describe('deleting a role (#56)', () => {
  it('refuses a held role and says how many hold it', async () => {
    const { service, deleted } = build(
      [{ id: 3, isSuperAdmin: false }],
      [
        { roleId: 3, userId: 1 },
        { roleId: 3, userId: 2 },
      ],
    );
    await expect(service.deleteRole(3)).rejects.toThrow(new BadRequestException(M.role.heldRoleDelete(2)));
    await expect(service.deleteRole(3)).rejects.toThrow('Դերը չի կարող ջնջվել․ այն ունի 2 կրող։');
    expect(deleted).toEqual([]);
  });

  it('deletes a role nobody holds', async () => {
    const { service, deleted } = build([{ id: 4, isSuperAdmin: false }], [{ roleId: 3, userId: 1 }]);
    await service.deleteRole(4);
    expect(deleted).toEqual([4]);
  });

  it('keeps refusing super-admin roles, held or not', async () => {
    const { service, deleted, count } = build([{ id: 1, isSuperAdmin: true }], []);
    await expect(service.deleteRole(1)).rejects.toThrow(new BadRequestException(M.role.superAdminUntouchable));
    expect(count).not.toHaveBeenCalled();
    expect(deleted).toEqual([]);
  });
});
