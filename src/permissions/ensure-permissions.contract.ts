import { BadRequestException } from '@nestjs/common';

/**
 * POST /api/internal/permissions/ensure — the request ai-api sends (2026-10-09).
 *
 * ai-api's skill registry (src/skills/registry/skill-permissions.ts) creates the
 * catalogue rows for AI skills through this route when its own database role
 * may not write to nairon_users:
 *
 *   body  { "names": ["use_ai_skills", "ai_skill_report_writer", …] }
 *
 * 1–101 names, every one matching SKILL_PERMISSION_NAME — the same pattern
 * ai-api checks before sending. Anything else, including one bad name among
 * good ones or a key other than `names`, is a 400 and nothing is written.
 * The route can only ever create rows in this namespace.
 */
export const SKILL_PERMISSION_NAME = /^(use_ai_skills|ai_skill_[a-z0-9_]{2,48})$/;
export const MIN_ENSURE_NAMES = 1;
/** use_ai_skills plus one ai_skill_<slug> per skill of a 100-skill import. */
export const MAX_ENSURE_NAMES = 101;

/** The names to ensure, de-duplicated in request order. Throws 400 on anything outside the contract. */
export function parseEnsurePermissionsRequest(body: unknown): string[] {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new BadRequestException('body must be {"names": [...]}');
  }
  const extra = Object.keys(body).filter((key) => key !== 'names');
  if (extra.length) throw new BadRequestException('only "names" is accepted');

  const names = (body as { names?: unknown }).names;
  if (!Array.isArray(names)) throw new BadRequestException('names must be an array');
  if (names.length < MIN_ENSURE_NAMES || names.length > MAX_ENSURE_NAMES) {
    throw new BadRequestException(`names must hold ${MIN_ENSURE_NAMES}–${MAX_ENSURE_NAMES} entries`);
  }
  const bad = names.findIndex((name) => typeof name !== 'string' || !SKILL_PERMISSION_NAME.test(name));
  if (bad !== -1) {
    throw new BadRequestException(`names[${bad}] is not use_ai_skills or ai_skill_<slug>`);
  }
  return [...new Set(names as string[])];
}
