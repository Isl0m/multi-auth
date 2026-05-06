import {
  IpAddress,
  Public,
  UserAgent,
} from '@/common/decorators/auth.decorator';
import {
  VerifyWebAuthnLoginDto,
  VerifyWebAuthnRegistrationDto,
} from '@/common/dto/webauthn.dto';
import { setAuthCookies } from '@/common/helpers/auth-cookies.helper';
import {
  BadRequestException,
  Body,
  Controller,
  Post,
  Req,
  Res,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { WebAuthnAuthService } from './webauthn-auth.service';

@Controller('auth/webauthn')
export class WebAuthnAuthController {
  constructor(private readonly webauthnService: WebAuthnAuthService) {}

  @Public()
  @Post('register/start')
  async startRegistration(
    @Body('email') email: string,
    @IpAddress() ipAddress: string,
    @UserAgent() userAgent: string,
  ) {
    if (!email) {
      throw new BadRequestException('Email is required');
    }
    return this.webauthnService.sendRegistrationEmail(
      email,
      ipAddress,
      userAgent,
    );
  }

  @Public()
  @Post('register/options')
  async getRegistrationOptions(
    @Body('token') token: string,
    @Res() res: Response,
  ) {
    if (!token) {
      throw new BadRequestException('Registration token is required');
    }
    const options =
      await this.webauthnService.generateRegistrationOptions(token);

    res.cookie('registrationChallenge', options.challenge, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 60000,
    });
    res.cookie('registrationToken', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 60000,
    });

    return res.send(options);
  }

  @Public()
  @Post('register/verify')
  async verifyRegistration(
    @Body() verifyDto: VerifyWebAuthnRegistrationDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const expectedChallenge = req.cookies['registrationChallenge'];
    const token = verifyDto.token || req.cookies['registrationToken'];

    if (!expectedChallenge || !token) {
      throw new BadRequestException(
        'Registration challenge or token not found or expired',
      );
    }
    const result = await this.webauthnService.verifyRegistration(
      token,
      verifyDto.credential,
      expectedChallenge,
      verifyDto.deviceName,
      req.ip,
      req.headers['user-agent'],
    );
    setAuthCookies(res, result);
    return result;
  }

  @Public()
  @Post('login/options')
  async getAuthenticationOptions(
    @Body('email') email: string,
    @Res() res: Response,
  ) {
    const { userId, ...options } =
      await this.webauthnService.generateAuthenticationOptions(email);

    res.cookie('authChallenge', options.challenge, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 60000,
    });
    res.cookie('authUserId', userId, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 60000,
    });

    return res.send(options);
  }

  @Public()
  @Post('login/verify')
  async verifyAuthentication(
    @Body() verifyDto: VerifyWebAuthnLoginDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
    @IpAddress() ipAddress: string,
    @UserAgent() userAgent: string,
  ) {
    const expectedChallenge = req.cookies['authChallenge'];
    const userId = req.cookies['authUserId'];

    if (!expectedChallenge || !userId) {
      throw new BadRequestException(
        'Authentication challenge or user context not found',
      );
    }

    const result = await this.webauthnService.verifyAuthentication(
      userId,
      verifyDto.credential,
      expectedChallenge,
      ipAddress,
      userAgent,
    );
    setAuthCookies(res, result);
    return result;
  }
}
