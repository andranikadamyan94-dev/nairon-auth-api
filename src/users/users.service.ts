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
    if (existing) throw new ConflictException(M.user.emailAlreadyExists);

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

  async getAllUsers() {
    const users = await this.prisma.user.findMany({
      orderBy: [{ firstName: 'asc' }, { lastName: 'asc' }],
      include: {
        roles: {
          include: { role: { include: { permissions: { include: { permission: true } } } } },
        },
      },
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
}