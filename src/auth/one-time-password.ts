/**
 * One-time-password sessions (2026-10-07; design in
 * claude-work/design/OTP-SERVER-ENFORCEMENT.md).
 *
 * An account in one-time-password state (`isOneTimePassword`) has a password
 * somebody else chose and handed over — HR at hiring, an admin's "set
 * one-time password". Until now its session was an ordinary one: the rule
 * "set your own password first" lived only in the sign-in screens, so whoever
 * knew the one-time password had the whole API until the owner replaced it.
 *
 * With ONE_TIME_PASSWORD_SESSIONS=true, the session of such an account is
 * marked in the token itself:
 *
 *     otp: true,  exp: one hour
 *
 * and the gateway and every domain guard let it do exactly two things: set
 * its new password (POST /users/password-reset in hr-api or crm-api) and read
 * /auth/me. The token is never upgraded — /auth/me ends it (401) once the
 * account has left the state, and the client signs in again with the new
 * password. Unset (the default), every session is minted as before.
 *
 * Off is also the rollback: a token already minted keeps its claim and its
 * hour, and stays restricted downstream, but no new one is marked.
 */

export const OTP_CLAIM = 'otp';

/** Long enough to choose a password; short enough that an abandoned one dies the same day. */
export const ONE_TIME_PASSWORD_SESSION_TTL_SEC = 60 * 60;

export function oneTimePasswordSessionsEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return env.ONE_TIME_PASSWORD_SESSIONS === 'true';
}

/** Present and not explicitly false — the same reading as the gateway and the domain guards. */
export function isOneTimePasswordToken(payload: unknown): boolean {
  if (!payload || typeof payload !== 'object') return false;
  const value = (payload as Record<string, unknown>)[OTP_CLAIM];
  return value !== undefined && value !== null && value !== false;
}

