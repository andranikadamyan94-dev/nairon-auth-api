import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  Res,
  UnauthorizedException,
} from "@nestjs/common";
import { ApiTags, ApiOperation, ApiBearerAuth } from "@nestjs/swagger";
import { SkipThrottle, Throttle } from "@nestjs/throttler";
import { Request, Response } from "express";
import { AuthService } from "./auth.service";
import { Public } from "./decorators/public.decorator";
import { LoginDto } from "./dtos/auth.dto";

const COOKIE_NAME = "nairon_session";
const COOKIE_OPTS = {
  httpOnly: true,
  sameSite: "strict" as const,
  maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days (matches JWT TTL)
  path: "/",
  secure: process.env.NODE_ENV === 'production',
};

/**
 * Duplicate session cookies (2026-09-08). A browser can hold TWO
 * nairon_session cookies for the gateway host: the host-only one we set, and
 * a stale parent-domain one (e.g. `.nairon.am`) from an earlier gateway
 * configuration. It sends both; cookie-parser keeps the first, which is the
 * OLD one — so /me answered with a previous person's identity and permissions
 * right after a fresh login, and logout (host-only clear) could never remove
 * it. Hard refresh doesn't help, incognito does — exactly the report.
 *
 * Two defences: read EVERY cookie value and prefer the newest token, and on
 * login/logout also send a parent-domain clear (the gateway now passes an
 * explicit Domain through).
 */
function sessionTokens(req: Request): string[] {
  const raw = req.headers.cookie ?? "";
  const values = raw
    .split(";")
    .map((p) => p.trim())
    .filter((p) => p.startsWith(COOKIE_NAME + "="))
    .map((p) => decodeURIComponent(p.slice(COOKIE_NAME.length + 1)));
  const iatOf = (t: string) => {
    try {
      const payload = JSON.parse(Buffer.from(t.split(".")[1], "base64url").toString("utf8"));
      return Number(payload?.iat ?? 0);
    } catch {
      return 0;
    }
  };
  return [...new Set(values)].sort((a, b) => iatOf(b) - iatOf(a));
}

/** `gateway.nairon.am` → `.nairon.am`; nothing for localhost / IPs. */
function parentDomainOf(req: Request): string | null {
  const host = String(req.headers["x-forwarded-host"] ?? req.headers.host ?? "").split(":")[0];
  const labels = host.split(".");
  if (labels.length < 3 || /^\d+$/.test(labels[labels.length - 1])) return null;
  return "." + labels.slice(1).join(".");
}

function clearStaleParentCookie(req: Request, res: Response) {
  const domain = parentDomainOf(req);
  if (domain) res.clearCookie(COOKIE_NAME, { path: "/", domain });
}

@ApiTags("auth")
@Controller("auth")
export class AuthController {
  constructor(private authService: AuthService) {}

  @HttpCode(HttpStatus.OK)
  @Public()
  @Throttle({ default: { ttl: 60_000, limit: 20 } })
  @Post(["login", "signin"])
  @ApiOperation({ summary: "Login" })
  async signIn(
    @Body() dto: LoginDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.authService.signIn(dto.email, dto.password);
    // Kill a stale parent-domain twin first so the fresh login is the only
    // session the browser holds.
    clearStaleParentCookie(req, res);
    res.cookie(COOKIE_NAME, result.access_token, COOKIE_OPTS);
    return result;
  }

  // Every app in every tab polls this for cross-app logout/permission sync —
  // it's cookie-gated and cheap, and throttling it only broke that feature.
  @SkipThrottle()
  @Public()
  @Get("me")
  @ApiOperation({ summary: "Get current session user" })
  async me(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const tokens = sessionTokens(req);
    if (!tokens.length) throw new UnauthorizedException();
    // Newest token first; a stale duplicate that no longer verifies is skipped.
    let lastError: unknown = null;
    for (const token of tokens) {
      try {
        const result = await this.authService.getMe(token);
        if (tokens.length > 1) clearStaleParentCookie(req, res);
        res.cookie(COOKIE_NAME, token, COOKIE_OPTS);
        return result;
      } catch (e) {
        lastError = e;
      }
    }
    throw lastError instanceof UnauthorizedException ? lastError : new UnauthorizedException();
  }

  @Public()
  @HttpCode(HttpStatus.OK)
  @Post("logout")
  @ApiOperation({ summary: "Clear session cookie" })
  logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    res.clearCookie(COOKIE_NAME, { path: "/" });
    clearStaleParentCookie(req, res);
    return { success: true };
  }

  @Get("profile")
  @ApiBearerAuth()
  @ApiOperation({ summary: "Get profile" })
  getProfile(@Req() req: Request) {
    return (req as any).user;
  }
}
