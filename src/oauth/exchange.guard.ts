import { CanActivate, ExecutionContext, Injectable, Logger, UnauthorizedException } from '@nestjs/common';

import { safeEquals } from './oauth.crypto';

/**
 * Guards the token exchange, and fails closed.
 *
 * This is deliberately not InternalGuard. That guard protects routes which
 * predate it and which several services already call, so it treats an unset
 * INTERNAL_SECRET as "this deployment cannot check yet" and lets the request
 * through — a rollout compromise that is correct for those routes and wrong
 * for this one.
 *
 * The exchange has no such history. Nothing called it yesterday, so refusing
 * everything until a secret is configured breaks nothing and closes the only
 * door between an OAuth token and a Nairon session token. A missing secret
 * here means the exchange is off, not open.
 *
 * It also uses its own variable rather than INTERNAL_SECRET, so that turning
 * the exchange on does not, as a side effect, switch InternalGuard from
 * fail-open to fail-closed across the users, roles and permissions controllers.
 */
@Injectable()
export class McpExchangeGuard implements CanActivate {
  private readonly logger = new Logger(McpExchangeGuard.name);
  private static warned = false;

  canActivate(context: ExecutionContext): boolean {
    const expected = process.env.MCP_EXCHANGE_SECRET;
    if (!expected) {
      if (!McpExchangeGuard.warned) {
        McpExchangeGuard.warned = true;
        this.logger.warn(
          'MCP_EXCHANGE_SECRET is not set — the OAuth token exchange is disabled. ' +
            'Set it on this service and on the MCP host to enable it.',
        );
      }
      throw new UnauthorizedException();
    }

    const req = context.switchToHttp().getRequest();
    const presented = String(req.headers['x-mcp-exchange-secret'] ?? '');
    if (!safeEquals(presented, expected)) throw new UnauthorizedException();
    return true;
  }
}
