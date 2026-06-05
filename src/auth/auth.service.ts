import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { M } from '../constants/messages';
import { JwtService } from '@nestjs/jwt';
import { AuthPrismaService } from '../prisma.service';
import * as bcrypt from 'bcryptjs';

@Injectable()
export class AuthService {
  constructor(
    private prisma: AuthPrismaService,
    private jwtService: JwtService,
  ) {}

  async signIn(email: string, pass: string) {
    const user = await this.prisma.user.findFirst({
      where: { email: email.toLowerCase().trim() },
      include: {
        roles: {
          include: {
            role: {
              include: {
                permissions: { include: { permission: true } },
              },
            },
          },
        },
      },
    });
    if (!user || !bcrypt.compareSync(pass, user.password)) {
      throw new BadRequestException(M.auth.invalidCredentials);
    }
    const { password, ...payload } = user;
    const compactRoles = payload.roles.map((r: any) => ({
      role: {
        level: r.role.level,
        permissions: Array.from(
          new Map(r.role.permissions.map((p: any) => [p.permissionId ?? p.permission?.id, p])).values()
        ),
      },
    }));
    return {
      access_token: await this.jwtService.signAsync({ id: payload.id, email: payload.email, isAdmin: payload.isAdmin, roles: compactRoles }),
      user: payload,
    };
  }

  async getMe(token: string) {
    try {
      const decoded = await this.jwtService.verifyAsync(token);
      const user = await this.prisma.user.findUnique({
        where: { id: decoded.id },
        include: {
          roles: {
            include: {
              role: {
                include: {
                  permissions: { include: { permission: true } },
                },
              },
            },
          },
        },
      });
      if (!user) throw new UnauthorizedException();
      const { password, ...payload } = user;
      return { access_token: token, user: payload };
    } catch {
      throw new UnauthorizedException();
    }
  }
}