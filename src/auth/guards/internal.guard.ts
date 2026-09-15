import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';

/**
 * Service-to-service authentication for the routes a browser never reaches.
 *
 * The users, roles and permissions controllers are called only by the other
 * back-end services — the gateway rewrites everything under its auth prefix to
 * /api/auth/..., so none of them is routable from outside. They were left
 * `@Public()` with no guard at all, which meant anything that could open a
 * socket to this service could read every account, change any password, or
 * delete any user. Matching the `x-internal-secret` header the rest of the
 * platform already uses closes that without inventing a new mechanism.
 */
@Injectable()
export class InternalGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const req = context.switchToHttp().getRequest();
    assertInternalSecret(req.headers?.['x-internal-secret']);
    return true;
  }
}

/**
 * The rule, failing closed on every uncertainty.
 *
 * WHAT WAS HERE BEFORE, AND WHY IT WAS A RELEASE BLOCKER
 *
 *     if (!expected) { warnOnce(); return true; }
 *
 * The reasoning was a rollout: ship the code, let callers start sending the
 * header, then set the secret and the check turns on. The first half shipped
 * and the second half did not — and because every route in the users, roles
 * and permissions controllers carries `@Public()`, this guard was the ONLY
 * authentication in front of them. An unset secret therefore meant: read every
 * account, create a user, delete a user, and assign any role to any user, with
 * no credential at all. Including the role that carries `ai_write_actions`.
 *
 * The rollout premise also turned out to be false. Every caller — crm-api's
 * and hr-api's user resolvers, warehouse-api's users service — already sends
 * the header. There was nothing left to wait for.
 *
 * A blank expected secret is the same thing as an absent one, and a blank
 * incoming header is not a credential: it is what a caller writing
 * `process.env.INTERNAL_SECRET ?? ''` sends when it is itself unconfigured.
 * Both are denied.
 */
export function assertInternalSecret(incoming: unknown): void {
  const expected = process.env.INTERNAL_SECRET;
  if (typeof expected !== 'string' || expected.trim() === '') {
    throw new UnauthorizedException('Internal authentication is not configured on this service');
  }
  if (typeof incoming !== 'string' || incoming === '' || incoming !== expected) {
    throw new UnauthorizedException();
  }
}

/**
 * The second layer, checked once at boot.
 *
 * The guard above fails closed on its own, so this is not what makes the
 * service safe — it is what makes a misconfiguration visible. Without it, an
 * auth-api started with no secret would refuse every internal call and the
 * symptom would surface somewhere else entirely: a members page reading "no
 * employees", a resolver returning empty, a support ticket about missing names.
 */
export function assertInternalAuthConfigured(): void {
  const expected = process.env.INTERNAL_SECRET;
  if (typeof expected !== 'string' || expected.trim() === '') {
    throw new Error(
      'INTERNAL_SECRET is not set. auth-api authenticates its internal users, roles and ' +
        'permissions routes with it — they carry no other credential — and refuses to start without it.',
    );
  }
}
