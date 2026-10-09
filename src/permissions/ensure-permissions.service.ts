import { Injectable, Logger } from '@nestjs/common';

import { AuthPrismaService } from '../prisma.service';

export interface EnsurePermissionsResult {
  /** Rows this call inserted, in request order. */
  created: string[];
  /** Rows that were already there, untouched, in request order. */
  existing: string[];
}

/**
 * Creates catalogue rows for AI skills. Grants nothing.
 *
 * The statement is the one migration 20261006120000_ai_dock_permissions uses
 * for its own rows — `INSERT INTO "Permission" ("name") … ON CONFLICT ("name")
 * DO NOTHING`; "Permission" has no other column to fill (id is serial). Unlike
 * that migration there is no second statement: "RolePermission" is never
 * written, so a new skill right reaches nobody until an admin ticks it for a
 * role on the roles screen.
 *
 * One statement for the whole list, so it is all-or-nothing, and `RETURNING`
 * reports exactly which rows this call inserted even when two calls race.
 * (Prisma 5.9's createMany + skipDuplicates writes the same rows but returns
 * only a count.)
 */
@Injectable()
export class EnsurePermissionsService {
  private readonly logger = new Logger(EnsurePermissionsService.name);

  constructor(private readonly prisma: AuthPrismaService) {}

  /** `names` must already have passed parseEnsurePermissionsRequest. */
  async ensure(names: readonly string[]): Promise<EnsurePermissionsResult> {
    const rows = await this.prisma.$queryRaw<{ name: string }[]>`
      INSERT INTO "Permission" ("name")
      SELECT unnest(${[...names]}::text[])
      ON CONFLICT ("name") DO NOTHING
      RETURNING "name"
    `;
    const inserted = new Set((rows ?? []).map((row) => row.name));
    const created = names.filter((name) => inserted.has(name));
    const existing = names.filter((name) => !inserted.has(name));
    if (created.length) this.logger.log(`created ${created.length} permission row(s), granted to no role: ${created.join(', ')}`);
    return { created, existing };
  }
}
