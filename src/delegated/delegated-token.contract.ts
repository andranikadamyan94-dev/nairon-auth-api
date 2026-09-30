import { BadRequestException } from '@nestjs/common';

/**
 * Delegated tokens for Nairon AI background work (V3 long-running goals, V5
 * workflows) — the contract, kept free of Nest wiring so it can be read and
 * tested on its own.
 *
 * A goal or a workflow runs with its owner's rights and nobody else's. ai-api
 * has no service account, so before every run it asks this service for a
 * token that says "this person, in this organisation, read-only, for this
 * goal, for the next five minutes". The person's status, organisation
 * membership and rights are read again at every mint; a token is never
 * cached or refreshed, so a change of rights lands at the next run.
 *
 * Everything here is off unless AUTH_DELEGATED_TOKENS_ENABLED is exactly
 * "true". Off, the route answers 404 as if it did not exist.
 */

/** Exactly five minutes. Not configurable: a longer-lived read token is a different design. */
export const DELEGATED_TOKEN_TTL_SEC = 300;

/** The only scope minted today. Writes after approval run on the approver's own session. */
export const DELEGATED_SCOPE_READ = 'read';

/** `src` claim, so logs and downstream audit can tell these tokens apart. */
export const DELEGATED_TOKEN_SRC = 'ai-delegated';

export type DelegatedActor = 'ai-goal' | 'ai-workflow';

/**
 * Rights the owner must hold, literally, in the organisation the run acts in.
 *
 * Read as grants, never implied by super admin — the same rule ai-api applies
 * to its rollout switches. The dedicated switches the designs name
 * (`ai_long_goals` for V3, `ai_workflow_author` for V5) are not in the
 * permission catalogue yet; they belong here, next to `use_ai_assistant`, in
 * the change that adds them to ALL_PERMISSIONS.
 */
export const REQUIRED_PERMISSIONS: Record<DelegatedActor, readonly string[]> = {
  'ai-goal': ['use_ai_assistant'],
  'ai-workflow': ['use_ai_assistant'],
};

export interface DelegatedTokenRequest {
  userId: number;
  entityId: number;
  actor: DelegatedActor;
  /** goalId for ai-goal, workflowId for ai-workflow. */
  subjectId: string;
  runId?: string;
  scope: typeof DELEGATED_SCOPE_READ;
}

/** The `act` claim (RFC 8693 actor): who is acting on the person's behalf. */
export type DelegatedActClaim =
  | { sub: 'ai-goal'; goalId: string; runId?: string }
  | { sub: 'ai-workflow'; workflowId: string; runId?: string };

export interface DelegatedTokenClaims {
  /** Same shape as a login token, so every downstream guard resolves the person as usual. */
  id: number;
  email: string;
  sub: string;
  entityId: number;
  scope: typeof DELEGATED_SCOPE_READ;
  act: DelegatedActClaim;
  src: typeof DELEGATED_TOKEN_SRC;
}

export function delegatedTokensEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return env.AUTH_DELEGATED_TOKENS_ENABLED === 'true';
}

/** Goal, workflow and run ids: uuids in practice; anything id-shaped is accepted, nothing else. */
const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$/;

function positiveInt(value: unknown): number | null {
  const n = typeof value === 'string' && /^\d+$/.test(value) ? Number(value) : value;
  return typeof n === 'number' && Number.isSafeInteger(n) && n > 0 ? n : null;
}

function optionalId(value: unknown, field: string): string | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'string' || !ID_PATTERN.test(value)) {
    throw new BadRequestException(`${field} is not a valid id`);
  }
  return value;
}

/**
 * Strict: anything unexpected is a 400, never a guess. In particular entityId
 * must be a real organisation — 0 means "every entity" to the downstream
 * permission resolvers and must never be delegated.
 */
export function parseDelegatedTokenRequest(body: unknown): DelegatedTokenRequest {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new BadRequestException('body must be a JSON object');
  }
  const b = body as Record<string, unknown>;

  const allowed = new Set(['userId', 'entityId', 'goalId', 'workflowId', 'runId', 'scope']);
  const unknown = Object.keys(b).filter((k) => !allowed.has(k));
  if (unknown.length) throw new BadRequestException(`unexpected field(s): ${unknown.join(', ')}`);

  const userId = positiveInt(b.userId);
  if (userId === null) throw new BadRequestException('userId must be a positive integer');
  const entityId = positiveInt(b.entityId);
  if (entityId === null) throw new BadRequestException('entityId must be a positive integer');

  if (b.scope !== DELEGATED_SCOPE_READ) {
    throw new BadRequestException(`scope must be "${DELEGATED_SCOPE_READ}"`);
  }

  const goalId = optionalId(b.goalId, 'goalId');
  const workflowId = optionalId(b.workflowId, 'workflowId');
  if ((goalId === undefined) === (workflowId === undefined)) {
    throw new BadRequestException('exactly one of goalId or workflowId is required');
  }
  const runId = optionalId(b.runId, 'runId');

  return {
    userId,
    entityId,
    actor: goalId !== undefined ? 'ai-goal' : 'ai-workflow',
    subjectId: (goalId ?? workflowId) as string,
    ...(runId !== undefined ? { runId } : {}),
    scope: DELEGATED_SCOPE_READ,
  };
}

export function actClaimFor(req: DelegatedTokenRequest): DelegatedActClaim {
  const run = req.runId !== undefined ? { runId: req.runId } : {};
  return req.actor === 'ai-goal'
    ? { sub: 'ai-goal', goalId: req.subjectId, ...run }
    : { sub: 'ai-workflow', workflowId: req.subjectId, ...run };
}
