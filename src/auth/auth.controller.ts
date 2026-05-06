import {
  CurrentUser,
  IpAddress,
  Public,
  UserAgent,
} from '@/common/decorators/auth.decorator';
import { setAuthCookies } from '@/common/helpers/auth-cookies.helper';
import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Res,
} from '@nestjs/common';
import type { Response } from 'express';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post('refresh')
  async refresh(
    @Body('refreshToken') refreshToken: string,
    @IpAddress() ipAddress: string,
    @UserAgent() userAgent: string,
    @Res({ passthrough: true }) res: Response,
  ) {
    const tokens = await this.authService.refreshAccessToken(
      refreshToken,
      ipAddress,
      userAgent,
    );
    setAuthCookies(res, tokens);
    return tokens;
  }

  @Post('logout')
  @HttpCode(HttpStatus.OK)
  async logout(
    @CurrentUser() user: { userId: string; email: string },
    @IpAddress() ipAddress: string,
    @UserAgent() userAgent: string,
    @Res({ passthrough: true }) res: Response,
  ) {
    await this.authService.logLogout(user.userId, ipAddress, userAgent);
    res.clearCookie('access_token');
    res.clearCookie('refresh_token');
    return { message: 'Logged out successfully' };
  }
}
