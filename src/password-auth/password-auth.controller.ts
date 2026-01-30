import {
  CurrentUser,
  IpAddress,
  Public,
  UserAgent,
} from '@/common/decorators/auth.decorator';
import {
  ChangePasswordDto,
  EnableMfaDto,
  LoginDto,
  RegisterDto,
  ResetPasswordDto,
  ResetPasswordRequestDto,
  VerifyMfaDto,
} from '@/common/dto/auth.dto';
import { JwtAuthGuard } from '@/common/guards/jwt-auth.guard';
import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Patch,
  Post,
  UseGuards,
} from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import { PasswordAuthService } from './password-auth.service';

@Controller('auth/password')
@UseGuards(JwtAuthGuard)
export class PasswordAuthController {
  constructor(private readonly passwordAuthService: PasswordAuthService) {}

  @Public()
  @Post('register')
  @Throttle({ default: { limit: 3, ttl: 60000 } })
  async register(
    @Body() registerDto: RegisterDto,
    @IpAddress() ipAddress: string,
    @UserAgent() userAgent: string,
  ) {
    return this.passwordAuthService.register(registerDto, ipAddress, userAgent);
  }

  @Public()
  @Post('login')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  async login(
    @Body() loginDto: LoginDto,
    @IpAddress() ipAddress: string,
    @UserAgent() userAgent: string,
  ) {
    return this.passwordAuthService.login(loginDto, ipAddress, userAgent);
  }

  @Get('mfa/qrcode')
  async generateMfaQrCode(@CurrentUser() user: any) {
    console.log(user);
    return this.passwordAuthService.generateMfaQrCode(user.userId);
  }

  @Post('mfa/enable')
  async enableMfa(
    @CurrentUser() user: any,
    @Body() enableMfaDto: EnableMfaDto,
  ) {
    return this.passwordAuthService.enableMfa(user.userId, enableMfaDto);
  }

  @Post('mfa/disable')
  async disableMfa(
    @CurrentUser() user: any,
    @Body() verifyMfaDto: VerifyMfaDto,
  ) {
    return this.passwordAuthService.disableMfa(user.userId, verifyMfaDto);
  }

  @Patch('change-password')
  async changePassword(
    @CurrentUser() user: any,
    @Body() changePasswordDto: ChangePasswordDto,
    @IpAddress() ipAddress: string,
    @UserAgent() userAgent: string,
  ) {
    return this.passwordAuthService.changePassword(
      user.userId,
      changePasswordDto,
      ipAddress,
      userAgent,
    );
  }

  @Public()
  @Post('reset-password/request')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 3, ttl: 60000 } })
  async requestPasswordReset(
    @Body() resetDto: ResetPasswordRequestDto,
    @IpAddress() ipAddress: string,
    @UserAgent() userAgent: string,
  ) {
    return this.passwordAuthService.requestPasswordReset(
      resetDto,
      ipAddress,
      userAgent,
    );
  }

  @Public()
  @Post('reset-password')
  @HttpCode(HttpStatus.OK)
  async resetPassword(
    @Body() resetDto: ResetPasswordDto,
    @IpAddress() ipAddress: string,
    @UserAgent() userAgent: string,
  ) {
    return this.passwordAuthService.resetPassword(
      resetDto,
      ipAddress,
      userAgent,
    );
  }
}
