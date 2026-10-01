import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { M } from '../constants/messages';
import { JwtService } from '@nestjs/jwt';
import { AuthPrismaService } from '../prisma.service';
import * as bcrypt from 'bcryptjs';

/** The user record every session response carries: roles, their permissions. */
const USER_SESSION_INCLUDE = {
  roles: {
    include: {
      role: {
        include: {
          permissions: { include: { permission: true } },
        },
      },
    },
  },
} as const;

@Injectable()
export class AuthService {
  constructor(
    private prisma: AuthPrismaService,
    private jwtService: JwtService,
  ) {}

  async signIn(email: string, pass: string) {
    const user = await this.prisma.user.findFirst({
      where: { email: email.toLowerCase().trim() },
      include: USER_SESSION_INCLUDE,
    });
    if (!user || !bcrypt.compareSync(pass, user.password)) {
      throw new BadRequestException(M.auth.invalidCredentials);
    }
    // Checked after the password so a wrong password on a deactivated account
    // still reads as bad credentials — the message must not tell an outsider
    // which addresses are real accounts.
    if (user.deactivatedAt) {
      throw new UnauthorizedException(M.auth.deactivated);
    }
    const { password, ...payload } = user;
    // No admin claim in the token: super-admin (level-0 role) is entity-scoped,
    // so every service resolves it per request against the selected entity.
    return {
      access_token: await this.jwtService.signAsync({ id: payload.id, email: payload.email }),
      user: payload,
    };
  }

  async getMe(token: string) {
    try {
      const decoded = await this.jwtService.verifyAsync(token);
      const user = await this.prisma.user.findUnique({
        where: { id: decoded.id },
        include: USER_SESSION_INCLUDE,
      });
      // A token issued before deactivation stays cryptographically valid for
      // its full 30 days, so the check has to happen here on every restore.
      if (!user || user.deactivatedAt) throw new UnauthorizedException();
      const { password, ...payload } = user;
      return { access_token: token, user: payload };
    } catch {
      throw new UnauthorizedException();
    }
  }

  /**
   * A fresh session for a person already proven by other means — the
   * cross-app handoff code (handoff/). Same shape and same token claims as
   * signIn; null for an unknown or deactivated account.
   */
  async sessionForUser(id: number) {
    const user = await this.prisma.user.findUnique({
      where: { id },
      include: USER_SESSION_INCLUDE,
    });
    if (!user || user.deactivatedAt) return null;
    const { password, ...payload } = user;
    return {
      access_token: await this.jwtService.signAsync({ id: payload.id, email: payload.email }),
      user: payload,
    };
  }
}
