import { Injectable, NotFoundException, ConflictException } from '@nestjs/common';
import { AuthPrismaService } from '../prisma.service';
import { M } from '../constants/messages';
import * as bcrypt from 'bcryptjs';
import { CreateUserDto, UpdateUserDto } from './dtos/user.dto';

@Injectable()
export class UsersService {
  constructor(private prisma: AuthPrismaService) {}

  async createUser(dto: CreateUserDto) {
    const existing = await this.prisma.user.findUnique({ where: { email: dto.email.toLowerCase().trim() } });
    // Same body shape as the PrismaExceptionFilter's P2002 response, so a form
    // can show this under the email input rather than as a bare toast.
    if (existing) {
      throw new ConflictException({
        statusCode: 409,
        message: M.user.emailAlreadyExists,
        fields: ['email'],
      });
    }

    const hashedPassword = await bcrypt.hash(dto.password, 10);
    const user = await this.prisma.user.create({
      data: { ...dto, email: dto.email.toLowerCase().trim(), password: hashedPassword },
    });
    const { password, ...result } = user;
    return result;
  }

  async getUserById(id: number) {
    const user = await this.prisma.user.findUnique({
      where: { id },
      include: {
        roles: {
          include: { role: { include: { permissions: { include: { permission: true } } } } },
        },
      },
    });
    if (!user) throw new NotFoundException(M.user.notFound);
    const { password, ...result } = user;
    return result;
  }

  /**
   * `includeInactive` is off by default so that every list in every service —
   * all of which reach this endpoint — drops deactivated people without having
   * to know they exist.
   *
   * The services pass it explicitly for the opposite job: turning a stored
   * userId back into a name on a historical record. A past task assignee or
   * payroll row must still name the person, not render a blank.
   */
  async getAllUsers(page = 1, limit = 100, includeInactive = false) {
    const users = await this.prisma.user.findMany({
      where: includeInactive ? undefined : { deactivatedAt: null },
      // id last: two people can share a name, and tied rows with no tiebreaker
      // may be arranged differently per query, which makes paged results skip
      // and repeat users.
      orderBy: [{ firstName: 'asc' }, { lastName: 'asc' }, { id: 'asc' }],
      include: {
        roles: {
          include: { role: { include: { permissions: { include: { permission: true } } } } },
        },
      },
      skip: (page - 1) * limit,
      take: limit,
    });
    return users.map(({ password, ...u }) => u);
  }

  async updateUser(id: number, dto: UpdateUserDto) {
    const data: any = { ...dto };
    if (dto.password) data.password = await bcrypt.hash(dto.password, 10);
    const user = await this.prisma.user.update({ where: { id }, data });
    const { password, ...result } = user;
    return result;
  }

  async resetPassword(id: number, newPassword: string) {
    const hashed = await bcrypt.hash(newPassword, 10);
    await this.prisma.user.update({
      where: { id },
      data: { password: hashed, isOneTimePassword: false },
    });
  }

  async deleteUser(id: number) {
    const user = await this.prisma.user.findUnique({ where: { id } });
    if (!user) throw new NotFoundException(M.user.notFound);
    await this.prisma.user.delete({ where: { id } });
  }

  /**
   * Offboarding. Idempotent: deactivating an already-deactivated user keeps the
   * original timestamp rather than moving it, so "when did they leave" survives
   * a double click.
   */
  async deactivateUser(id: number) {
    const user = await this.prisma.user.findUnique({ where: { id } });
    if (!user) throw new NotFoundException(M.user.notFound);
    if (user.deactivatedAt) {
      const { password, ...result } = user;
      return result;
    }

    // The last account that can administer users must stay usable, or nobody
    // can reactivate anyone — including this one.
    await this.assertNotLastAdmin(id);

    const updated = await this.prisma.user.update({
      where: { id },
      data: { deactivatedAt: new Date() },
    });
    const { password, ...result } = updated;
    return result;
  }

  async reactivateUser(id: number) {
    const user = await this.prisma.user.findUnique({ where: { id } });
    if (!user) throw new NotFoundException(M.user.notFound);
    const updated = await this.prisma.user.update({
      where: { id },
      data: { deactivatedAt: null },
    });
    const { password, ...result } = updated;
    return result;
  }

  /**
   * Admin here means what the guards mean by it: any role at level 0
   * (the isAdmin flag is gone — level 0 is the only admin concept).
   */
  private async assertNotLastAdmin(id: number) {
    const admins = await this.prisma.user.findMany({
      where: {
        deactivatedAt: null,
        roles: { some: { role: { level: 0 } } },
      },
      select: { id: true },
    });
    if (admins.length === 1 && admins[0].id === id) {
      throw new ConflictException(M.user.lastAdmin);
    }
  }
}