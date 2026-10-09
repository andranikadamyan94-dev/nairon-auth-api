import { CanActivate, ExecutionContext, ForbiddenException, Injectable } from '@nestjs/common';

/**
 * Refuses a request that has passed through a reverse proxy (2026-10-09).
 *
 * For internal routes that only a service on the Docker network calls,
 * connecting straight to this container (ai-api's AUTH_API_URL is the
 * container's own address, e.g. http://auth-api:3002 — the gateway cannot
 * reach /api/internal/* at all). Every public way in is a proxy:
 * the gateway forwards with `xfwd: true` (X-Forwarded-For/-Host/-Proto/-Port),
 * and nginx, in front of the gateway and of the auth.nairon.am vhost, is the
 * place X-Real-IP / X-Forwarded-For are set. A header that says "I was forwarded" therefore means
 * "this did not come from inside", and the request is refused before
 * INTERNAL_SECRET is even looked at — so no public path can be used to guess it.
 *
 * Presence is all that is checked. Forwarded headers are client-controlled and
 * are never TRUSTED for anything (no allow-listing by req.ip or by their
 * values): a caller can add one, which only gets it refused, but cannot strip
 * the ones a proxy in front of it appends. This is the second layer;
 * InternalGuard's secret is the first.
 */
export const PROXY_HEADERS = [
  'forwarded',
  'x-forwarded-for',
  'x-forwarded-host',
  'x-forwarded-proto',
  'x-forwarded-port',
  'x-forwarded-prefix',
  'x-real-ip',
  'via',
] as const;

export function cameThroughProxy(headers: Record<string, unknown> | undefined): boolean {
  if (!headers) return false;
  return PROXY_HEADERS.some((name) => headers[name] !== undefined);
}

@Injectable()
export class DirectCallOnlyGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const req = context.switchToHttp().getRequest();
    if (cameThroughProxy(req?.headers)) throw new ForbiddenException();
    return true;
  }
}
