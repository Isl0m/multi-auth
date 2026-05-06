import {
  IpAddress,
  Public,
  UserAgent,
} from '@/common/decorators/auth.decorator';
import {
  PasswordlessLoginDto,
  VerifyMagicLinkDto,
} from '@/common/dto/auth.dto';
import { setAuthCookies } from '@/common/helpers/auth-cookies.helper';
import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Res,
} from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import type { Response } from 'express';
import { PasswordlessAuthService } from './passwordless-auth.service';

@Controller('auth/passwordless')
export class PasswordlessAuthController {
  constructor(
    private readonly passwordlessAuthService: PasswordlessAuthService,
  ) {}

  @Public()
  @Post('send-magic-link')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 3, ttl: 60000 } })
  async sendMagicLink(
    @Body() loginDto: PasswordlessLoginDto,
    @IpAddress() ipAddress: string,
    @UserAgent() userAgent: string,
  ) {
    return this.passwordlessAuthService.sendMagicLink(
      loginDto,
      ipAddress,
      userAgent,
    );
  }

  @Public()
  @Post('verify')
  @HttpCode(HttpStatus.OK)
  async verifyMagicLink(
    @Body() verifyDto: VerifyMagicLinkDto,
    @IpAddress() ipAddress: string,
    @UserAgent() userAgent: string,
    @Res({ passthrough: true }) res: Response,
  ) {
    const result = await this.passwordlessAuthService.verifyMagicLink(
      verifyDto,
      ipAddress,
      userAgent,
    );
    setAuthCookies(res, result);
    return result;
  }
}
