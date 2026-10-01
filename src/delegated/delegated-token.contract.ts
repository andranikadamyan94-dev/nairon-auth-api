import { BadRequestException } from '@nestjs/common';

/**
 * Delegated tokens for Nairon AI background work (V3 long-running goals, V5
 * workflows) — the contract, kept free of Nest wiring so it can be read and
 * tested on its own.
 *
 * A goal or a workflow runs with a person's rights and nobody else's. ai-api
 * has no service account, so before every run (or workflow step) it asks this
 * service for a token that says "this person, in this organisation,
 * read-only, for this goal / this workflow version, for the next five
 * minutes". The person's status, organisation membership and rights are read
 * again at every mint; a token is never cached or refreshed, so a change of
 * rights lands at the next run.
 *
 *   POST /api/internal/delegated-token
 *   x-internal-secret: INTERNAL_SECRET
 *
 *   goal:     { userId, entityId, goalId, runId?, scope: "read" }
 *   workflow: { userId, entityId, workflowId, workflowVersionId,
 *               role?: "author" | "approver" (default "author"), runId?, scope: "read" }
 *
 *   200 { access_token, token_type: "Bearer", expires_in: 300, scope: "read",
 *         entity_id, act }
 *       act (goal)     = { sub: "ai-goal", goalId, runId? }
 *       act (workflow) = { sub: "ai-workflow", workflowId, workflowVersionId, role, runId? }
 *   400 malformed body (unknown field, both/neither id, workflow without
 *       workflowVersionId, bad role, workflowVersionId/role on a goal, ...)
 *   403 { error: "delegation_refused", reason }   suspend, do not retry
 *   404 the flag (or, for a workflow, the workflow sub-flag) is off
 *   503 { error: "membership_unavailable" }       retry later
 *
 * Everything here is off unless AUTH_DELEGATED_TOKENS_ENABLED is exactly
 * "true". Off, the route answers 404 as if it did not exist. The workflow form
 * additionally needs AUTH_DELEGATED_WORKFLOW_TOKENS_ENABLED exactly "true";
 * without it a workflow request gets that same 404 (after the secret is
 * checked and the body parses), while goal requests are unaffected.
 */

/** Exactly five minutes. Not configurable: a longer-lived read token is a different design. */
export const DELEGATED_TOKEN_TTL_SEC = 300;

/** The only scope minted today. Writes after approval run on the approver's own session. */
export const DELEGATED_SCOPE_READ = 'read';

/** `src` claim, so logs and downstream audit can tell these tokens apart. */
export const DELEGATED_TOKEN_SRC = 'ai-delegated';

export type DelegatedActor = 'ai-goal' | 'ai-workflow';

/**
 * In whose capacity a workflow token is asked for. `author`: the workflow runs
 * as the person who wrote it. `approver`: ai-api reads, as the person it is
 * about to ask for an approval, what that person would see.
 */
export type DelegatedWorkflowRole = 'author' | 'approver';
export const DELEGATED_WORKFLOW_ROLES: readonly DelegatedWorkflowRole[] = ['author', 'approver'];

/** Which rights set a request is checked against. */
export type DelegatedPermissionKey = 'ai-goal' | 'ai-workflow:author' | 'ai-workflow:approver';

/**
 * Rights the person must hold, literally, in the organisation the run acts in.
 *
 * Read as grants, never implied by super admin — the same rule ai-api applies
 * to its rollout switches. Losing any of them suspends the run at its next
 * mint.
 *
 *   ai-goal              the assistant + `ai_long_goals` (V3 goals).
 *   ai-workflow:author   the assistant + `ai_workflow_author` (V5 workflows).
 *   ai-workflow:approver the assistant only.
 *
 * Why the approver set does not widen anything: an approver is given nothing
 * new. ai-api checks the AUTHOR's rights itself before it asks anybody, and
 * separately checks `ai_write_actions` for the person it asks; this token only
 * lets ai-api read, as that person, what that person can already read. ai-api
 * can already obtain an 'ai-goal' read token (use_ai_assistant +
 * ai_long_goals) for any member, and the approver token has exactly the same
 * power: read-only, five minutes, one organisation, with the account, the
 * grant and organisation membership re-checked at every mint. Dropping the
 * dedicated switch changes who may be read as, not what the token can do.
 */
export const REQUIRED_PERMISSIONS: Record<DelegatedPermissionKey, readonly string[]> = {
  'ai-goal': ['use_ai_assistant', 'ai_long_goals'],
  'ai-workflow:author': ['use_ai_assistant', 'ai_workflow_author'],
  'ai-workflow:approver': ['use_ai_assistant'],
};

export function permissionKeyFor(req: Pick<DelegatedTokenRequest, 'actor' | 'role'>): DelegatedPermissionKey {
  if (req.actor === 'ai-goal') return 'ai-goal';
  // parse always sets a role on a workflow request; were one ever missing,
  // the stricter author set applies, never the approver one.
  return req.role === 'approver' ? 'ai-workflow:approver' : 'ai-workflow:author';
}

export function requiredPermissions(req: Pick<DelegatedTokenRequest, 'actor' | 'role'>): readonly string[] {
  return REQUIRED_PERMISSIONS[permissionKeyFor(req)];
}

export interface DelegatedTokenRequest {
  userId: number;
  entityId: number;
  actor: DelegatedActor;
  /** goalId for ai-goal, workflowId for ai-workflow. */
  subjectId: string;
  /** ai-workflow only (required there): the frozen version the run executes. */
  workflowVersionId?: string;
  /** ai-workflow only (always set there, "author" by default). */
  role?: DelegatedWorkflowRole;
  runId?: string;
  scope: typeof DELEGATED_SCOPE_READ;
}

/** The `act` claim (RFC 8693 actor): who is acting on the person's behalf. */
export type DelegatedActClaim =
  | { sub: 'ai-goal'; goalId: string; runId?: string }
  | {
      sub: 'ai-workflow';
      workflowId: string;
      workflowVersionId: string;
      role: DelegatedWorkflowRole;
      runId?: string;
    };

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

/** The workflow form: both the read flag and its own sub-flag, each exactly "true". */
export function delegatedWorkflowTokensEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return delegatedTokensEnabled(env) && env.AUTH_DELEGATED_WORKFLOW_TOKENS_ENABLED === 'true';
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

  const allowed = new Set(['userId', 'entityId', 'goalId', 'workflowId', 'workflowVersionId', 'role', 'runId', 'scope']);
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
  const run = runId !== undefined ? { runId } : {};

  if (goalId !== undefined) {
    // Present at all — even null — is a caller that thinks it is asking for a workflow.
    const stray = ['workflowVersionId', 'role'].filter((k) => k in b);
    if (stray.length) throw new BadRequestException(`unexpected field(s) for a goal: ${stray.join(', ')}`);
    return { userId, entityId, actor: 'ai-goal', subjectId: goalId, ...run, scope: DELEGATED_SCOPE_READ };
  }

  const workflowVersionId = optionalId(b.workflowVersionId, 'workflowVersionId');
  if (workflowVersionId === undefined) {
    throw new BadRequestException('workflowVersionId is required with workflowId');
  }
  let role: DelegatedWorkflowRole = 'author';
  if ('role' in b) {
    if (!DELEGATED_WORKFLOW_ROLES.includes(b.role as DelegatedWorkflowRole)) {
      throw new BadRequestException(`role must be one of: ${DELEGATED_WORKFLOW_ROLES.join(', ')}`);
    }
    role = b.role as DelegatedWorkflowRole;
  }

  return {
    userId,
    entityId,
    actor: 'ai-workflow',
    subjectId: workflowId as string,
    workflowVersionId,
    role,
    ...run,
    scope: DELEGATED_SCOPE_READ,
  };
}

export function actClaimFor(req: DelegatedTokenRequest): DelegatedActClaim {
  const run = req.runId !== undefined ? { runId: req.runId } : {};
  if (req.actor === 'ai-goal') return { sub: 'ai-goal', goalId: req.subjectId, ...run };
  // parse guarantees both; a request built any other way without them is refused, not guessed.
  if (req.workflowVersionId === undefined || req.role === undefined) {
    throw new BadRequestException('workflowVersionId and role are required for a workflow');
  }
  return {
    sub: 'ai-workflow',
    workflowId: req.subjectId,
    workflowVersionId: req.workflowVersionId,
    role: req.role,
    ...run,
  };
}
