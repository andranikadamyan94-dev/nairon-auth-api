import { readFileSync, readdirSync } from 'fs';
import { join } from 'path';

import { RolesService } from '../roles/roles.service';
import { AI_DOCK_MARKER_PERMISSION, AI_DOCK_PERMISSIONS, ALL_PERMISSIONS, PermissionsService, RETIRED_PERMISSIONS } from './permissions.service';

describe('Օրվա ամփոփման և առաջադրանքների վերլուծության միասնական իրավունք', () => {
  it('ունի միայն մեկ ai_task_analysis անուն՝ առանց ավտոմատ և ձեռքով տարբերակների', () => {
    expect(ALL_PERMISSIONS.filter(p => p === 'ai_task_analysis')).toEqual(['ai_task_analysis']);
    expect(ALL_PERMISSIONS).not.toContain('ai_daily_review');
    expect(ALL_PERMISSIONS).not.toContain('ai_task_analysis_auto');
  });
  it('ավելացնում է կատալոգի իրավունքը, բայց չի նշանակում որևէ դերի կամ աշխատակցի', async () => {
    const upsert = jest.fn().mockResolvedValue({});
    const service = new PermissionsService({ permission: { upsert } } as any);
    await service.seedPermissions();
    expect(upsert).toHaveBeenCalledWith({ where: { name: 'ai_task_analysis' }, create: { name: 'ai_task_analysis' }, update: {} });
    expect(upsert).toHaveBeenCalledTimes(ALL_PERMISSIONS.length);
  });
});

describe('Կատալոգի հարցումների իրավունքը (view_catalog_requests, 2026-10-01)', () => {
  it('կատալոգում է ճիշտ մեկ անգամ և թաքցված (retired) չէ', () => {
    expect(ALL_PERMISSIONS.filter((p) => p === 'view_catalog_requests')).toEqual(['view_catalog_requests']);
    expect(RETIRED_PERMISSIONS).not.toContain('view_catalog_requests');
  });
  it('seed-ը գրում է միայն Permission տողը՝ ոչ մի դերի չի նշանակում', async () => {
    const upsert = jest.fn().mockResolvedValue({});
    await new PermissionsService({ permission: { upsert } } as any).seedPermissions();
    expect(upsert).toHaveBeenCalledWith({ where: { name: 'view_catalog_requests' }, create: { name: 'view_catalog_requests' }, update: {} });
  });
});

describe('Նախագծի կրկնօրինակման իրավունքը (duplicate_project, 2026-10-07)', () => {
  it('կատալոգում է ճիշտ մեկ անգամ և թաքցված (retired) չէ', () => {
    expect(ALL_PERMISSIONS.filter((p) => p === 'duplicate_project')).toEqual(['duplicate_project']);
    expect(RETIRED_PERMISSIONS).not.toContain('duplicate_project');
  });
  it('seed-ը գրում է միայն Permission տողը՝ ոչ մի դերի չի նշանակում', async () => {
    const upsert = jest.fn().mockResolvedValue({});
    await new PermissionsService({ permission: { upsert } } as any).seedPermissions();
    expect(upsert).toHaveBeenCalledWith({ where: { name: 'duplicate_project' }, create: { name: 'duplicate_project' }, update: {} });
    expect(upsert).toHaveBeenCalledTimes(ALL_PERMISSIONS.length);
  });
});

const OBJECT_TAB_PERMISSIONS = [
  'view_object_people', 'view_object_subobjects', 'view_object_materials', 'view_object_estimate',
  'view_object_finance', 'view_object_requests', 'view_object_assets',
];

describe('Շինարարական օբյեկտի ներդիրների իրավունքները (view_object_*, 2026-10-05)', () => {
  it('յոթն էլ կատալոգում են ճիշտ մեկ անգամ և թաքցված (retired) չեն', () => {
    for (const name of OBJECT_TAB_PERMISSIONS) {
      expect(ALL_PERMISSIONS.filter((p) => p === name)).toEqual([name]);
      expect(RETIRED_PERMISSIONS).not.toContain(name);
    }
  });
  it('seed-ը գրում է միայն Permission տողերը՝ ոչ մի դերի չի նշանակում', async () => {
    const upsert = jest.fn().mockResolvedValue({});
    await new PermissionsService({ permission: { upsert } } as any).seedPermissions();
    for (const name of OBJECT_TAB_PERMISSIONS) {
      expect(upsert).toHaveBeenCalledWith({ where: { name }, create: { name }, update: {} });
    }
    expect(upsert).toHaveBeenCalledTimes(ALL_PERMISSIONS.length);
  });
});

/*
 * Nairon AI V2–V5 switches. Each is a literal grant the owner ticks per role;
 * being in the catalogue must hand it to nobody, super-admin roles included.
 */
const AI_V2_V5 = ['ai_memory', 'ai_memory_publish', 'ai_memory_manage', 'ai_long_goals', 'ai_relations_analysis', 'ai_workflow_author', 'ai_workflow_publisher', 'ai_workflow_view', 'ai_standing_approvals'];

/** A Prisma stand-in that records every model call and answers each with `answer`. */
function recordingPrisma(answer: (model: string, method: string, args: any) => any = () => ({})) {
  const calls: { model: string; method: string; args: any }[] = [];
  const prisma = new Proxy({} as any, {
    get: (_t, model: string) =>
      new Proxy({} as any, {
        get: (_m, method: string) => async (args: any) => {
          calls.push({ model, method, args });
          return answer(model, method, args);
        },
      }),
  });
  return { prisma, calls };
}

describe('Nairon AI V2–V5 իրավունքները կատալոգում', () => {
  it.each(AI_V2_V5)('%s կատալոգում է՝ ճիշտ մեկ անգամ', (name) => {
    expect(ALL_PERMISSIONS.filter((p) => p === name)).toEqual([name]);
  });

  it('թաքցված (retired) չեն, ուրեմն դերերի էջում երևում են', async () => {
    for (const name of AI_V2_V5) expect(RETIRED_PERMISSIONS).not.toContain(name);
    const { prisma, calls } = recordingPrisma(() => []);
    await new PermissionsService(prisma).getAllPermissions();
    expect(calls).toEqual([
      { model: 'permission', method: 'findMany', args: { where: { name: { notIn: RETIRED_PERMISSIONS } }, orderBy: { name: 'asc' } } },
    ]);
  });

  it('seed-ը գրում է միայն Permission տողեր՝ ոչ մի դերի, super-admin-ի կամ աշխատակցի չի նշանակում', async () => {
    const { prisma, calls } = recordingPrisma();
    await new PermissionsService(prisma).seedPermissions();

    // Only permission.upsert, once per catalogue name — no RolePermission, UserRole or Role call.
    expect(calls.every((c) => c.model === 'permission' && c.method === 'upsert')).toBe(true);
    expect(calls).toHaveLength(ALL_PERMISSIONS.length);

    for (const name of AI_V2_V5) {
      const call = calls.find((c) => c.args.where.name === name);
      // Bare row: no nested `roles` create; an existing row is left exactly as it is.
      expect(call?.args).toEqual({ where: { name }, create: { name }, update: {} });
    }
  });

  it('seed-ը կրկնելիս նոր բան չի անում (idempotent upsert, update: {})', async () => {
    const { prisma, calls } = recordingPrisma();
    const service = new PermissionsService(prisma);
    await service.seedPermissions();
    await service.seedPermissions();
    expect(calls).toHaveLength(2 * ALL_PERMISSIONS.length);
    expect(calls.every((c) => JSON.stringify(c.args.update) === '{}')).toBe(true);
  });

  it('ոչ մի միգրացիա չի ավելացնում կամ նշանակում այս իրավունքները', () => {
    const dir = join(__dirname, '..', '..', 'prisma', 'migrations');
    const sql = readdirSync(dir, { withFileTypes: true })
      .filter((d) => d.isDirectory())
      .map((d) => readFileSync(join(dir, d.name, 'migration.sql'), 'utf8'))
      .join('\n');
    for (const name of AI_V2_V5) expect(sql).not.toContain(name);
  });

  it('super-admin դերին API-ով նշանակել հնարավոր չէ, և ոչինչ չի գրվում', async () => {
    const { prisma, calls } = recordingPrisma((model, method) =>
      model === 'role' && method === 'findUnique' ? { isSuperAdmin: true } : {},
    );
    await expect(new RolesService(prisma).assignPermissionsToRole(1, AI_V2_V5)).rejects.toThrow();
    expect(calls.map((c) => `${c.model}.${c.method}`)).toEqual(['role.findUnique']);
  });
});

/*
 * Screen agent (2026-10-05): `use_ai_screen`. In the catalogue and visible on
 * the roles screen; its migration adds the bare Permission row and grants it to
 * nobody — granting is the owner's, per role.
 */
describe('use_ai_screen — ԱԲ-ն կարող է աշխատել էկրանով', () => {
  const MIGRATION = join(__dirname, '..', '..', 'prisma', 'migrations', '20261005120000_permission_use_ai_screen', 'migration.sql');

  it('կատալոգում է ճիշտ մեկ անգամ և թաքցված չէ', () => {
    expect(ALL_PERMISSIONS.filter((p) => p === 'use_ai_screen')).toEqual(['use_ai_screen']);
    expect(RETIRED_PERMISSIONS).not.toContain('use_ai_screen');
  });

  it('seed-ը գրում է միայն Permission տողը', async () => {
    const { prisma, calls } = recordingPrisma();
    await new PermissionsService(prisma).seedPermissions();
    const call = calls.find((c) => c.args.where.name === 'use_ai_screen');
    expect(call).toEqual({ model: 'permission', method: 'upsert', args: { where: { name: 'use_ai_screen' }, create: { name: 'use_ai_screen' }, update: {} } });
  });

  it('միգրացիան ավելացնում է միայն Permission տողը՝ idempotent, ոչ մի դերի չի նշանակում', () => {
    const sql = readFileSync(MIGRATION, 'utf8')
      .split('\n')
      .filter((l) => !l.trim().startsWith('--'))
      .join('\n');
    expect(sql).toMatch(/INSERT INTO "Permission" \("name"\)\s+VALUES \('use_ai_screen'\)\s+ON CONFLICT \("name"\) DO NOTHING;/);
    expect(sql).not.toMatch(/RolePermission|UserRole|"Role"/);
    expect(sql).not.toMatch(/\b(UPDATE|DELETE)\b/i);
  });
});

/*
 * AI dock controls (2026-10-06): nine per-role switches. Unlike the rows above,
 * the migration grants them — to every role that holds use_ai_assistant, in the
 * same organisation — so nobody loses a control until an admin unticks it;
 * ai_mode_screen only where use_ai_screen is held today.
 */
describe('AI dock controls — ai_mode_* / ai_dock_*', () => {
  const DOCK = [
    'ai_mode_auto', 'ai_mode_screen', 'ai_dock_saved', 'ai_dock_history', 'ai_dock_export',
    'ai_dock_workflows', 'ai_dock_new_chat', 'ai_dock_attach', 'ai_dock_voice',
  ];
  const MIGRATION = join(__dirname, '..', '..', 'prisma', 'migrations', '20261006120000_ai_dock_permissions', 'migration.sql');
  const sql = () => readFileSync(MIGRATION, 'utf8').split('\n').filter((l) => !l.trim().startsWith('--')).join('\n');

  it('all nine are in the catalogue exactly once and not retired', () => {
    for (const name of DOCK) {
      expect(ALL_PERMISSIONS.filter((p) => p === name)).toEqual([name]);
      expect(RETIRED_PERMISSIONS).not.toContain(name);
    }
  });

  it('the seed writes only their Permission rows', async () => {
    const upsert = jest.fn().mockResolvedValue({});
    await new PermissionsService({ permission: { upsert } } as any).seedPermissions();
    for (const name of DOCK) expect(upsert).toHaveBeenCalledWith({ where: { name }, create: { name }, update: {} });
  });

  it('the migration adds the nine rows, idempotently', () => {
    const text = sql();
    expect(text).toMatch(/INSERT INTO "Permission" \("name"\) VALUES[\s\S]+?ON CONFLICT \("name"\) DO NOTHING;/);
    for (const name of DOCK) expect(text).toContain(`('${name}')`);
    expect(text).not.toMatch(/\b(UPDATE|DELETE|DROP|ALTER|TRUNCATE)\b/i);
    expect(text.match(/ON CONFLICT/g)).toHaveLength(3);
  });

  it('grants eight to every holder of use_ai_assistant and ai_mode_screen only to holders of use_ai_screen, in the same organisation', () => {
    const [, eight, screen] = sql().split(/INSERT INTO /).slice(1).map((s) => s);
    expect(eight).toContain(`assistant.name = 'use_ai_assistant'`);
    expect(eight).toContain('rp."entityId"');
    for (const name of DOCK.filter((n) => n !== 'ai_mode_screen')) expect(eight).toContain(`'${name}'`);
    expect(eight).not.toContain('ai_mode_screen');
    expect(screen).toContain(`screen.name = 'use_ai_screen'`);
    expect(screen).toContain(`name = 'ai_mode_screen'`);
    expect(screen).toContain('rp."entityId"');
  });
});

/*
 * AI dock marker (2026-10-06): the tenth dock control, «Նշել էջում». Granted like the eight — to every role holding
 * use_ai_assistant, in the same organisation — and kept OUT of the nine the session's aiDockPermissions marker counts.
 */
describe('AI dock marker — ai_dock_marker', () => {
  const MIGRATION = join(__dirname, '..', '..', 'prisma', 'migrations', '20261006160000_ai_dock_marker', 'migration.sql');
  const sql = () => readFileSync(MIGRATION, 'utf8').split('\n').filter((l) => !l.trim().startsWith('--')).join('\n');

  it('is in the catalogue exactly once, not retired, and not one of the nine the session marker counts', () => {
    expect(AI_DOCK_MARKER_PERMISSION).toBe('ai_dock_marker');
    expect(ALL_PERMISSIONS.filter((p) => p === 'ai_dock_marker')).toEqual(['ai_dock_marker']);
    expect(RETIRED_PERMISSIONS).not.toContain('ai_dock_marker');
    expect(AI_DOCK_PERMISSIONS).toHaveLength(9);
    expect(AI_DOCK_PERMISSIONS as readonly string[]).not.toContain('ai_dock_marker');
  });

  it('the seed writes its Permission row', async () => {
    const upsert = jest.fn().mockResolvedValue({});
    await new PermissionsService({ permission: { upsert } } as any).seedPermissions();
    expect(upsert).toHaveBeenCalledWith({ where: { name: 'ai_dock_marker' }, create: { name: 'ai_dock_marker' }, update: {} });
  });

  it('the migration adds the row and grants it to every holder of use_ai_assistant in the same organisation, idempotently', () => {
    const text = sql();
    expect(text).toMatch(/INSERT INTO "Permission" \("name"\) VALUES\s+\('ai_dock_marker'\)\s+ON CONFLICT \("name"\) DO NOTHING;/);
    expect(text).not.toMatch(/\b(UPDATE|DELETE|DROP|ALTER|TRUNCATE)\b/i);
    expect(text.match(/ON CONFLICT/g)).toHaveLength(2);
    const [, grant] = text.split(/INSERT INTO /).slice(1);
    expect(grant).toContain(`assistant.name = 'use_ai_assistant'`);
    expect(grant).toContain(`name = 'ai_dock_marker'`);
    expect(grant).toContain('rp."entityId"');
    expect(grant).not.toMatch(/use_ai_screen|ai_mode_screen/);
  });
});
