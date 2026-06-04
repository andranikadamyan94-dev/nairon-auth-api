import { Body, Controller, Get, HttpCode, HttpStatus, Post, Req, Res, UnauthorizedException } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiBearerAuth } from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import { Request, Response } from 'express';
import { AuthService } from './auth.service';
import { Public } from './decorators/public.decorator';
import { LoginDto } from './dtos/auth.dto';

const COOKIE_NAME = 'nairon_session';
const COOKIE_OPTS = {
  httpOnly: true,
  sameSite: 'strict' as const,
  maxAge: 60 * 60 * 1000, // 1 hour
  path: '/',
};

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @HttpCode(HttpStatus.OK)
  @Public()
  @Throttle({ default: { ttl: 60_000, limit: 5 } })
  @Post('login')
  @ApiOperation({ summary: 'Login' })
  async signIn(
    @Body() dto: LoginDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.authService.signIn(dto.email, dto.password);
    res.cookie(COOKIE_NAME, result.access_token, COOKIE_OPTS);
    return result;
  }

  @Public()
  @Get('me')
  @ApiOperation({ summary: 'Get current session user' })
  async me(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const token = req.cookies?.[COOKIE_NAME];
    if (!token) throw new UnauthorizedException();
    const result = await this.authService.getMe(token);
    res.cookie(COOKIE_NAME, token, COOKIE_OPTS);
    return result;
  }

  @Public()
  @HttpCode(HttpStatus.OK)
  @Post('logout')
  @ApiOperation({ summary: 'Clear session cookie' })
  logout(@Res({ passthrough: true }) res: Response) {
    res.clearCookie(COOKIE_NAME, { path: '/' });
    return { success: true };
  }

  @Get('profile')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get profile' })
  getProfile(@Req() req: Request) {
    return (req as any).user;
  }
}
