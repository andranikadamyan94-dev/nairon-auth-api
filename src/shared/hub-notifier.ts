import { Logger } from '@nestjs/common';

/**
 * One notice for the hr-api notification hub (phase 3, 2026-10-07).
 * The shape POST /api/notifications/internal accepts for a single recipient.
 */
export interface HubNotice {
  userId: number;
  /** Catalog key, e.g. system.app_access_granted. */
  type: string;
  title: string;
  body: string;
  url?: string;
  email?: { subject?: string; details?: { label: string; value: string }[] };
}

/**
 * auth-api's only way to tell a person something: hand it to hr-api, which
 * owns the bell, push and email (and the person's preferences).
 *
 * Best effort by design. A notice is never a reason for a sign-in, a token
 * exchange or a revocation to fail, so `notify` never throws and never rejects:
 * it answers true when hr-api accepted the notice, false otherwise. Nothing
 * secret is logged — not the header, not the body, only the type and status.
 *
 * Configuration is read once, at construction, from variables this service
 * already has: HR_API_URL (also used by the delegated-token and OAuth
 * workspace calls) and the shared INTERNAL_SECRET (HR_INTERNAL_SECRET as a
 * fallback, the name the OAuth config uses for hr-api's secret).
 * A plain class, not a provider: its owner constructs it (and a test swaps it).
 */
export class HubNotifier {
  private readonly logger = new Logger(HubNotifier.name);
  private readonly base: string | undefined;
  private readonly secret: string | undefined;

  constructor(env: NodeJS.ProcessEnv = process.env, private readonly timeoutMs = 5000) {
    this.base = env.HR_API_URL?.trim().replace(/\/+$/, '') || undefined;
    const usable = (v?: string) => (v && v.trim() ? v : undefined);
    this.secret = usable(env.INTERNAL_SECRET) ?? usable(env.HR_INTERNAL_SECRET);
  }

  async notify(notice: HubNotice): Promise<boolean> {
    try {
      if (!this.base || !this.secret) {
        this.logger.warn(`notice ${notice.type} not sent: HR_API_URL or INTERNAL_SECRET is not set`);
        return false;
      }
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);
      try {
        const response = await fetch(`${this.base}/api/notifications/internal`, {
          method: 'POST',
          headers: { 'content-type': 'application/json', 'x-internal-secret': this.secret },
          body: JSON.stringify(notice),
          signal: controller.signal,
        });
        if (!response.ok) {
          this.logger.warn(`notice ${notice.type} refused by hr-api (HTTP ${response.status})`);
          return false;
        }
        return true;
      } finally {
        clearTimeout(timer);
      }
    } catch (error) {
      this.logger.warn(`notice ${notice.type} not delivered: ${(error as Error)?.name ?? 'error'}`);
      return false;
    }
  }
}
