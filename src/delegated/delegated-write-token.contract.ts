import { BadRequestException } from '@nestjs/common';

import { safeEquals } from '../oauth/oauth.crypto';

/**
 * V3.4 «Կանխավ հաստատում» — the write identity of ONE standing approval
 * (design V3-long-running-goals.md §3.2), kept free of Nest wiring.
 *
 * A person may approve, once and by a click, "when this goal's check holds, do
 * exactly this". When it holds, ai-api needs to make that one call as the
 * person. The goal's delegated READ token never writes (gateway and domains
 * refuse anything but GET on it), so ai-api asks here for a second, narrower
 * token:
 *
 *   POST /api/internal/delegated-write-token
 *   x-goal-write-secret: AI_GOALS_WRITE_TOKEN_SECRET     (never INTERNAL_SECRET)
 *   { userId, entityId, goalId, runId, approvalId, tool, scope: "write", target }
 *
 *   200 { access_token, token_type: "Bearer", expires_in ≤ 300,
 *         scope: "goal:write:<tool>:<approvalId>", entity_id, target,
 *         act: { sub: "ai-goal", goalId, runId, approvalId } }
 *   403 { error: "delegation_refused", reason }   the owner lost a right
 *
 * `target` is the one record the approval froze, signed into the token:
 *   chat.messages.send             { chatId }
 *   warehouse.reservations.create  { taskId, itemId, quantity[, projectId] }
 *
 * The gateway and the owning domain accept such a token on exactly that tool's
 * own routes (preflight and mutation), only on that target, only with
 * X-Entity-ID = entity_id, and re-check the organisation and the rights
 * themselves.
 *
 * Off unless AUTH_DELEGATED_WRITE_TOKENS_ENABLED is exactly "true": the route
 * then answers 404 as if it did not exist. It does not depend on the read
 * token's flag, and switching the read flag on never enables this route.
 */

/** Two minutes: one run makes one preflight and one mutation, seconds apart. The client caps at 300. */
export const DELEGATED_WRITE_TOKEN_TTL_SEC = 120;

export const WRITE_SCOPE_PREFIX = 'goal:write:';

/**
 * Rights the owner must hold LITERALLY in the organisation, at every mint:
 * the assistant, goals, AI writes and the standing-approval switch itself.
 * Super admin does not stand in for any of them (design §3.1.6).
 */
export const WRITE_REQUIRED_AI_PERMISSIONS = [
  'use_ai_assistant',
  'ai_long_goals',
  'ai_write_actions',
  'ai_standing_approvals',
] as const;

/**
 * The tools a standing approval may name — the same two ai-api's
 * STANDING_WHITELIST holds, and no others. Adding one is a code change here,
 * in the gateway's allow-map and in the owning domain, and a security review.
 *
 * `anyOf`: the business right the domain route itself accepts, held literally
 * (never via super admin). An empty list means the domain has no right for it
 * and decides per record — a chat message is allowed to a chat's members, and
 * crm-api checks membership on the call.
 */
export interface WriteToolRule {
  anyOf: readonly string[];
  /** The target's fields: every `required` one, any `optional` one, nothing else — positive integers. */
  target: { required: readonly string[]; optional: readonly string[] };
}

export const WRITE_TOOLS: Readonly<Record<string, WriteToolRule>> = Object.freeze({
  // warehouse-api POST /reservations and its preflight: @Permissions('view_warehouse', 'manage_reservations'),
  // with manage_warehouse as the warehouse super-permission. Target: the frozen task, the one item and its exact quantity.
  'warehouse.reservations.create': Object.freeze({
    anyOf: Object.freeze(['view_warehouse', 'manage_reservations', 'manage_warehouse']),
    target: Object.freeze({ required: Object.freeze(['taskId', 'itemId', 'quantity']), optional: Object.freeze(['projectId']) }),
  }),
  // crm-api POST /chats/:id/messages: no permission, the sender must be a member of the chat. Target: that chat.
  'chat.messages.send': Object.freeze({
    anyOf: Object.freeze([] as string[]),
    target: Object.freeze({ required: Object.freeze(['chatId']), optional: Object.freeze([] as string[]) }),
  }),
});

export type WriteTarget = Readonly<Record<string, number>>;

export const isWriteTool = (tool: string): boolean => Object.prototype.hasOwnProperty.call(WRITE_TOOLS, tool);

export const writeScopeFor = (tool: string, approvalId: string): string => `${WRITE_SCOPE_PREFIX}${tool}:${approvalId}`;

export interface DelegatedWriteTokenRequest {
  userId: number;
  entityId: number;
  goalId: string;
  runId: string;
  approvalId: string;
  tool: string;
  scope: 'write';
  target: WriteTarget;
}

export interface DelegatedWriteActClaim {
  sub: 'ai-goal';
  goalId: string;
  runId: string;
  approvalId: string;
}

export interface DelegatedWriteTokenClaims {
  id: number;
  email: string;
  sub: string;
  entityId: number;
  scope: string;
  act: DelegatedWriteActClaim;
  target: WriteTarget;
  src: 'ai-delegated';
}

export function delegatedWriteTokensEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return env.AUTH_DELEGATED_WRITE_TOKENS_ENABLED === 'true';
}

/**
 * The secret this route is authenticated with, or null when it may not be
 * used at all: unset, blank, shorter than 32 characters, or equal to any other
 * secret this service holds (INTERNAL_SECRET above all — the pilot/internal
 * path is never a write identity). Fail closed on every one of them.
 */
export function goalWriteSecret(env: NodeJS.ProcessEnv = process.env): string | null {
  const secret = env.AI_GOALS_WRITE_TOKEN_SECRET;
  if (typeof secret !== 'string' || secret.trim() === '' || secret.length < 32) return null;
  for (const other of [env.INTERNAL_SECRET, env.MCP_EXCHANGE_SECRET, env.JWT_SECRET, env.HR_INTERNAL_SECRET]) {
    if (typeof other === 'string' && other !== '' && safeEquals(secret, other)) return null;
  }
  return secret;
}

/** Constant time; anything but a non-empty string presented is a no. */
export function goalWriteSecretMatches(presented: unknown, env: NodeJS.ProcessEnv = process.env): boolean {
  const expected = goalWriteSecret(env);
  if (!expected) return false;
  if (typeof presented !== 'string' || presented === '') return false;
  return safeEquals(presented, expected);
}

/** Goal, run and approval ids: uuids in practice; anything id-shaped is accepted, nothing else. */
const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}$/;
/** dotted lower-case tool names, as ai-api registers them. */
const TOOL_PATTERN = /^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$/;

function positiveInt(value: unknown): number | null {
  const n = typeof value === 'string' && /^\d+$/.test(value) ? Number(value) : value;
  return typeof n === 'number' && Number.isSafeInteger(n) && n > 0 ? n : null;
}

function requiredId(value: unknown, field: string): string {
  if (typeof value !== 'string' || !ID_PATTERN.test(value)) {
    throw new BadRequestException(`${field} is not a valid id`);
  }
  return value;
}

/**
 * Strict: every field required, anything unexpected is a 400, never a guess.
 * A tool outside WRITE_TOOLS is a 400 too — that is ai-api asking for
 * something this contract never offered (a bug to fix), not the owner losing
 * a right, so it must not read as `delegation_refused`.
 */
export function parseDelegatedWriteTokenRequest(body: unknown): DelegatedWriteTokenRequest {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new BadRequestException('body must be a JSON object');
  }
  const b = body as Record<string, unknown>;

  const allowed = new Set(['userId', 'entityId', 'goalId', 'runId', 'approvalId', 'tool', 'scope', 'target']);
  const unknown = Object.keys(b).filter((k) => !allowed.has(k));
  if (unknown.length) throw new BadRequestException(`unexpected field(s): ${unknown.join(', ')}`);

  const userId = positiveInt(b.userId);
  if (userId === null) throw new BadRequestException('userId must be a positive integer');
  const entityId = positiveInt(b.entityId);
  if (entityId === null) throw new BadRequestException('entityId must be a positive integer');
  if (b.scope !== 'write') throw new BadRequestException('scope must be "write"');

  const goalId = requiredId(b.goalId, 'goalId');
  const runId = requiredId(b.runId, 'runId');
  const approvalId = requiredId(b.approvalId, 'approvalId');

  if (typeof b.tool !== 'string' || !TOOL_PATTERN.test(b.tool)) throw new BadRequestException('tool is not a valid tool name');
  if (!isWriteTool(b.tool)) throw new BadRequestException('tool cannot be pre-approved');

  const target = parseWriteTarget(b.tool, b.target);

  return { userId, entityId, goalId, runId, approvalId, tool: b.tool, scope: 'write', target };
}

/**
 * The record this token is for, exactly as the tool's rule shapes it: JSON
 * numbers (never strings), positive safe integers, required fields present,
 * nothing extra. Returned in canonical key order.
 */
export function parseWriteTarget(tool: string, raw: unknown): WriteTarget {
  const rule = WRITE_TOOLS[tool]?.target;
  if (!rule) throw new BadRequestException('tool cannot be pre-approved');
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw new BadRequestException('target must be an object');
  const t = raw as Record<string, unknown>;
  const known = new Set([...rule.required, ...rule.optional]);
  const extra = Object.keys(t).filter((k) => !known.has(k));
  if (extra.length) throw new BadRequestException(`unexpected target field(s): ${extra.join(', ')}`);
  const out: Record<string, number> = {};
  for (const key of [...rule.required, ...rule.optional].sort()) {
    const v = t[key];
    if (v === undefined && !rule.required.includes(key)) continue;
    if (typeof v !== 'number' || !Number.isSafeInteger(v) || v <= 0) throw new BadRequestException(`target.${key} must be a positive integer`);
    out[key] = v;
  }
  return Object.freeze(out);
}
