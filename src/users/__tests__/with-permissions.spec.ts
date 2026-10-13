import { UsersService } from '../users.service';
import { RolesService } from '../../roles/roles.service';
import { UsersController } from '../users.controller';
import { RolesController } from '../../roles/roles.controller';

/**
 * Opt-in slim shapes (perf audit 2026-10-13, 1.8): `?withPermissions=false`
 * leaves each role's permission catalogue out. Without the flag the response
 * is exactly what it always was — AI tools and the HR client read it.
 */
const FULL_ROLES = { roles: { include: { role: { include: { permissions: { include: { permission: true } } } } } } };
const SLIM_ROLES = { roles: { include: { role: true } } };

const prismaSpy = () => {
  const prisma: any = {
    user: {
      findMany: jest.fn(async () => [{ id: 1, password: 'x', firstName: 'A' }]),
      findUnique: jest.fn(async () => ({ id: 1, password: 'x', firstName: 'A' })),
    },
    role: { findMany: jest.fn(async () => []) },
  };
  return prisma;
};

describe('GET /users, /users/:id — withPermissions', () => {
  it('default: roles with their permission catalogue, as before', async () => {
    const prisma = prismaSpy();
    const ctl = new UsersController(new UsersService(prisma));
    await ctl.findAll();
    await ctl.findOne(1);
    expect(prisma.user.findMany.mock.calls[0][0].include).toEqual(FULL_ROLES);
    expect(prisma.user.findUnique.mock.calls[0][0].include).toEqual(FULL_ROLES);
  });

  it('withPermissions=false: the roles alone; nothing else in the query changes', async () => {
    const prisma = prismaSpy();
    const ctl = new UsersController(new UsersService(prisma));
    await ctl.findAll('1', '10000', 'true', undefined, 'false');
    await ctl.findAll('1', '10000', 'true', undefined);
    const [slim, full] = prisma.user.findMany.mock.calls.map((c: any[]) => c[0]);
    expect(slim.include).toEqual(SLIM_ROLES);
    expect({ ...slim, include: undefined }).toEqual({ ...full, include: undefined });
    const users = await ctl.findOne(1, 'false');
    expect(prisma.user.findUnique.mock.calls[0][0].include).toEqual(SLIM_ROLES);
    expect(users).not.toHaveProperty('password');
  });

  it('only the literal "false" opts out', async () => {
    const prisma = prismaSpy();
    await new UsersController(new UsersService(prisma)).findOne(1, '0');
    expect(prisma.user.findUnique.mock.calls[0][0].include).toEqual(FULL_ROLES);
  });
});

describe('GET /roles — withPermissions', () => {
  it('default includes the grant rows; false leaves them out', async () => {
    const prisma = prismaSpy();
    const ctl = new RolesController(new RolesService(prisma) as any);
    await ctl.findAll(undefined, 'true');
    await ctl.findAll(undefined, 'true', 'false');
    const [full, slim] = prisma.role.findMany.mock.calls.map((c: any[]) => c[0]);
    expect(full.include).toEqual({ permissions: { include: { permission: true } } });
    expect(slim.include).toBeUndefined();
    expect(slim.where).toEqual(full.where);
    expect(slim.orderBy).toEqual(full.orderBy);
  });
});
