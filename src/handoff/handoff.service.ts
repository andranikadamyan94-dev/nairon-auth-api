import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';

import { AuthService } from '../auth/auth.service';
import { M } from '../constants/messages';
import { randomToken, sha256 } from '../oauth/oauth.crypto';
import { AuthPrismaService } from '../prisma.service';
import { HANDOFF_CODE_PATTERN, handoffTtlSec } from './handoff.contract';

/** Expired rows older than this are pruned whenever a new code is issued. */
const PRUNE_AFTER_MS = 10 * 60 * 1000;

@Injectable()
export class HandoffService {
  private readonly logger = new Logger('AuthHandoff');

  constructor(
    private readonly prisma: AuthPrismaService,
    private readonly auth: AuthService,
  ) {}

  /** A fresh code for `userId`, usable once, by `targetOrigin` only, for handoffTtlSec() seconds. */
  async issue(userId: number, targetOrigin: string, now: Date = new Date()) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, deactivatedAt: true },
    });
    if (!user || user.deactivatedAt) throw new UnauthorizedException(M.auth.handoffSessionOnly);

    const code = randomToken(32);
    const ttl = handoffTtlSec();
    await this.prisma.authHandoffCode.create({
      data: {
        codeHash: sha256(code),
        userId,
        targetOrigin,
        expiresAt: new Date(now.getTime() + ttl * 1000),
      },
    });
    // Best effort: the table only ever holds the last few minutes.
    this.prisma.authHandoffCode
      .deleteMany({ where: { expiresAt: { lt: new Date(now.getTime() - PRUNE_AFTER_MS) } } })
      .catch(() => undefined);

    // Never the code itself.
    this.logger.log(`handoff code issued user=${userId} target=${targetOrigin} ttl=${ttl}s`);
    return { code, expiresIn: ttl };
  }

  /**
   * Trade a code for a session, once.
   *
   * Every failure answers the same 401, so a caller learns nothing about which
   * check failed. A code presented from the wrong origin is burnt on the spot:
   * it has evidently leaked, and the real destination falls back to sign-in.
   */
  async exchange(code: unknown, origin: string | undefined, now: Date = new Date()) {
    const invalid = () => new UnauthorizedException(M.auth.handoffInvalid);
    if (typeof code !== 'string' || !HANDOFF_CODE_PATTERN.test(code) || !origin) throw invalid();

    const codeHash = sha256(code);
    const record = await this.prisma.authHandoffCode.findUnique({ where: { codeHash } });
    if (!record) throw invalid();

    if (record.targetOrigin !== origin) {
      await this.prisma.authHandoffCode.updateMany({
        where: { codeHash, consumedAt: null },
        data: { consumedAt: now },
      });
      this.logger.warn(`handoff code presented from a foreign origin user=${record.userId} origin=${origin} — burnt`);
      throw invalid();
    }

    // The single-use guarantee: only the request that flips consumedAt from
    // null wins, however many arrive at once.
    const spent = await this.prisma.authHandoffCode.updateMany({
      where: { codeHash, consumedAt: null, expiresAt: { gt: now } },
      data: { consumedAt: now },
    });
    if (spent.count !== 1) {
      if (record.consumedAt) this.logger.warn(`handoff code replayed user=${record.userId}`);
      throw invalid();
    }

    const session = await this.auth.sessionForUser(record.userId);
    if (!session) throw invalid();
    this.logger.log(`handoff code exchanged user=${record.userId} target=${origin}`);
    return session;
  }
}
