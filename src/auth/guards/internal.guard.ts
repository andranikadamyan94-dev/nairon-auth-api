import { CanActivate, ExecutionContext, Injectable, Logger, UnauthorizedException } from '@nestjs/common';

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
  private static warned = false;
  private readonly logger = new Logger(InternalGuard.name);

  canActivate(context: ExecutionContext): boolean {
    const expected = process.env.INTERNAL_SECRET;

    // Unset means this deployment cannot verify anything, so refusing every
    // internal call would take the whole platform down rather than secure it.
    // The rollout is: ship the code (callers start sending the header), then
    // set the secret here, which turns the check on. This warns loudly on every
    // boot in between so the second half does not get forgotten.
    if (!expected) {
      if (!InternalGuard.warned) {
        InternalGuard.warned = true;
        this.logger.error(
          'INTERNAL_SECRET is not set — internal user/role/permission routes are UNAUTHENTICATED. ' +
            'Set it on this service to enable the check.',
        );
      }
      return true;
    }

    const req = context.switchToHttp().getRequest();
    if (req.headers['x-internal-secret'] !== expected) {
      throw new UnauthorizedException();
    }
    return true;
  }
}
