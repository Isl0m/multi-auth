import { AuthService } from '@/auth/auth.service';
import { Env } from '@/config/configuration';
import { db } from '@/db';
import { passwordAuth, passwordResetTokens, users } from '@/db/schema';
import { EmailService } from '@/email/email.service';
import { SecurityService } from '@/security/security.service';
import {
  ChangePasswordDto,
  EnableMfaDto,
  LoginDto,
  RegisterDto,
  ResetPasswordDto,
  ResetPasswordRequestDto,
  VerifyMfaDto,
} from '@common/dto/auth.dto';
import {
  BadRequestException,
  ConflictException,
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import { and, eq, isNull } from 'drizzle-orm';
import * as QRCode from 'qrcode';
import * as speakeasy from 'speakeasy';

@Injectable()
export class PasswordAuthService {
  private readonly bcryptSaltRounds: number;

  constructor(
    private readonly configService: ConfigService<Env, true>,
    private readonly securityService: SecurityService,
    private readonly emailService: EmailService,
    private readonly authService: AuthService,
  ) {
    this.bcryptSaltRounds = this.configService.get('BCRYPT_SALT_ROUNDS', {
      infer: true,
    });
  }

  async register(
    registerDto: RegisterDto,
    ipAddress: string,
    userAgent: string,
  ) {
    const { email, password, firstName, lastName } = registerDto;

    // Check if user already exists
    const existingUser = await db.query.users.findFirst({
      where: eq(users.email, email.toLowerCase()),
    });

    if (existingUser) {
      throw new ConflictException('User with this email already exists');
    }

    // Check password against common passwords list (simplified)
    if (this.isCommonPassword(password)) {
      throw new BadRequestException(
        'Password is too common. Please choose a stronger password',
      );
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, this.bcryptSaltRounds);

    // Create user and password auth record in a transaction
    const { newUser } = await db.transaction(async (tx) => {
      const [user] = await tx
        .insert(users)
        .values({
          email: email.toLowerCase(),
          firstName,
          lastName,
          emailVerified: false,
        })
        .returning();

      await tx.insert(passwordAuth).values({
        userId: user.id,
        passwordHash,
        passwordChangedAt: new Date(),
      });

      return { newUser: user };
    });
    const tokens = await this.authService.generateTokens(
      newUser.id,
      ipAddress,
      userAgent,
    );
    // Log security event
    await this.securityService.logSecurityEvent({
      userId: newUser.id,
      eventType: 'registration',
      authMethod: 'password',
      ipAddress,
      userAgent,
      success: true,
    });

    return {
      user: this.authService.sanitizeUser(newUser),
      ...tokens,
    };
  }

  async login(loginDto: LoginDto, ipAddress: string, userAgent: string) {
    const { email, password, totpCode } = loginDto;

    // Find user
    const user = await db.query.users.findFirst({
      where: eq(users.email, email.toLowerCase()),
      with: {
        passwordAuth: true,
      },
    });

    if (!user || !user.passwordAuth) {
      await this.securityService.logSecurityEvent({
        userId: null,
        eventType: 'login_failure',
        authMethod: 'password',
        ipAddress,
        userAgent,
        success: false,
        errorMessage: 'Invalid credentials',
      });
      throw new UnauthorizedException('Invalid email or password');
    }

    // Check if account is locked
    if (user.isLocked && user.lockoutUntil && user.lockoutUntil > new Date()) {
      const remainingTime = Math.ceil(
        (user.lockoutUntil.getTime() - Date.now()) / 1000 / 60,
      );
      throw new UnauthorizedException(
        `Account is locked. Please try again in ${remainingTime} minutes`,
      );
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(
      password,
      user.passwordAuth.passwordHash,
    );

    if (!isPasswordValid) {
      await this.handleFailedLogin(user.id, ipAddress, userAgent);
      throw new UnauthorizedException('Invalid email or password');
    }

    // Check MFA if enabled
    if (user.passwordAuth.mfaEnabled && user.passwordAuth.mfaSecret) {
      if (!totpCode) {
        return {
          requiresMfa: true,
          message: 'MFA code required',
        };
      }

      const isMfaValid = speakeasy.totp.verify({
        secret: user.passwordAuth.mfaSecret,
        encoding: 'base32',
        token: totpCode,
        window: 2,
      });

      if (!isMfaValid) {
        await this.handleFailedLogin(user.id, ipAddress, userAgent);
        throw new UnauthorizedException('Invalid MFA code');
      }
    }

    // Reset failed login attempts
    await db
      .update(users)
      .set({
        failedLoginAttempts: 0,
        isLocked: false,
        lockoutUntil: null,
        lastLoginAt: new Date(),
        lastLoginIp: ipAddress,
      })
      .where(eq(users.id, user.id));

    // Log successful login
    await this.securityService.logSecurityEvent({
      userId: user.id,
      eventType: 'login_success',
      authMethod: 'password',
      ipAddress,
      userAgent,
      success: true,
    });

    // Generate tokens
    const tokens = await this.authService.generateTokens(
      user.id,
      ipAddress,
      userAgent,
    );

    return {
      user: this.authService.sanitizeUser(user),
      ...tokens,
    };
  }

  async enableMfa(userId: string, enableMfaDto: EnableMfaDto) {
    const user = await db.query.users.findFirst({
      where: eq(users.id, userId),
      with: {
        passwordAuth: true,
      },
    });

    if (!user || !user.passwordAuth) {
      throw new UnauthorizedException('User not found');
    }

    if (user.passwordAuth.mfaEnabled) {
      throw new BadRequestException('MFA is already enabled');
    }

    // Generate MFA secret
    const secretToVerify = enableMfaDto.secret;

    // Verify the provided code
    const isValid = speakeasy.totp.verify({
      secret: secretToVerify,
      encoding: 'base32',
      token: enableMfaDto.totpCode,
      window: 2,
    });

    if (!isValid) {
      throw new BadRequestException('Invalid MFA code');
    }

    // Enable MFA
    await db
      .update(passwordAuth)
      .set({
        mfaEnabled: true,
        mfaSecret: secretToVerify,
      })
      .where(eq(passwordAuth.userId, userId));

    // Log security event
    await this.securityService.logSecurityEvent({
      userId,
      eventType: 'mfa_enabled',
      authMethod: 'password',
      ipAddress: null,
      userAgent: null,
      success: true,
    });

    return {
      message: 'MFA enabled successfully',
      secret: secretToVerify,
    };
  }

  async disableMfa(userId: string, verifyMfaDto: VerifyMfaDto) {
    const user = await db.query.users.findFirst({
      where: eq(users.id, userId),
      with: {
        passwordAuth: true,
      },
    });

    if (!user || !user.passwordAuth) {
      throw new UnauthorizedException('User not found');
    }

    if (!user.passwordAuth.mfaEnabled || !user.passwordAuth.mfaSecret) {
      throw new BadRequestException('MFA is not enabled');
    }

    // Verify the provided code
    const isValid = speakeasy.totp.verify({
      secret: user.passwordAuth.mfaSecret,
      encoding: 'base32',
      token: verifyMfaDto.totpCode,
      window: 2,
    });

    if (!isValid) {
      throw new BadRequestException('Invalid MFA code');
    }

    // Disable MFA
    await db
      .update(passwordAuth)
      .set({
        mfaEnabled: false,
        mfaSecret: null,
      })
      .where(eq(passwordAuth.userId, userId));

    // Log security event
    await this.securityService.logSecurityEvent({
      userId,
      eventType: 'mfa_disabled',
      authMethod: 'password',
      ipAddress: null,
      userAgent: null,
      success: true,
    });

    return {
      message: 'MFA disabled successfully',
    };
  }

  async generateMfaQrCode(userId: string) {
    const user = await db.query.users.findFirst({
      where: eq(users.id, userId),
    });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    // Generate MFA secret
    const secret = speakeasy.generateSecret({
      name: `Auth System (${user.email})`,
      length: 32,
    });

    // Guard clause to handle the undefined case
    if (!secret.otpauth_url) {
      throw new InternalServerErrorException('Failed to generate MFA Auth URL');
    }

    // Generate QR code
    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

    return {
      secret: secret.base32,
      qrCode: qrCodeUrl,
    };
  }

  async changePassword(
    userId: string,
    changePasswordDto: ChangePasswordDto,
    ipAddress: string,
    userAgent: string,
  ) {
    const { currentPassword, newPassword } = changePasswordDto;

    const user = await db.query.users.findFirst({
      where: eq(users.id, userId),
      with: {
        passwordAuth: true,
      },
    });

    if (!user || !user.passwordAuth) {
      throw new UnauthorizedException('User not found');
    }

    // Verify current password
    const isPasswordValid = await bcrypt.compare(
      currentPassword,
      user.passwordAuth.passwordHash,
    );

    if (!isPasswordValid) {
      throw new UnauthorizedException('Current password is incorrect');
    }

    // Check if new password is the same as current
    const isSamePassword = await bcrypt.compare(
      newPassword,
      user.passwordAuth.passwordHash,
    );

    if (isSamePassword) {
      throw new BadRequestException(
        'New password must be different from current password',
      );
    }

    // Hash new password
    const newPasswordHash = await bcrypt.hash(
      newPassword,
      this.bcryptSaltRounds,
    );

    // Update password
    await db
      .update(passwordAuth)
      .set({
        passwordHash: newPasswordHash,
        passwordChangedAt: new Date(),
      })
      .where(eq(passwordAuth.userId, userId));

    // Log security event
    await this.securityService.logSecurityEvent({
      userId,
      eventType: 'password_reset',
      authMethod: 'password',
      ipAddress,
      userAgent,
      success: true,
    });

    return {
      message: 'Password changed successfully',
    };
  }

  async requestPasswordReset(
    resetDto: ResetPasswordRequestDto,
    ipAddress: string,
    userAgent: string,
  ) {
    const { email } = resetDto;

    const user = await db.query.users.findFirst({
      where: eq(users.email, email.toLowerCase()),
      with: {
        passwordAuth: true,
      },
    });

    // Always return success to prevent email enumeration
    if (!user || !user.passwordAuth) {
      return {
        message: 'If the email exists, a password reset link has been sent',
      };
    }

    // Generate reset token
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    // Save reset token
    await db.insert(passwordResetTokens).values({
      userId: user.id,
      token,
      expiresAt,
    });

    // Send reset email
    const resetUrl = `${this.configService.get('FRONTEND_URL', { infer: true })}/reset-password?token=${token}`;
    await this.emailService.sendPasswordResetEmail(user.email, resetUrl);

    return {
      message: 'If the email exists, a password reset link has been sent',
    };
  }

  async resetPassword(
    resetDto: ResetPasswordDto,
    ipAddress: string,
    userAgent: string,
  ) {
    const { token, newPassword } = resetDto;

    // Find reset token
    const resetToken = await db.query.passwordResetTokens.findFirst({
      where: and(
        eq(passwordResetTokens.token, token),
        isNull(passwordResetTokens.usedAt),
      ),
    });

    if (!resetToken || resetToken.expiresAt < new Date()) {
      throw new BadRequestException('Invalid or expired reset token');
    }

    // Find user
    const user = await db.query.users.findFirst({
      where: eq(users.id, resetToken.userId),
      with: {
        passwordAuth: true,
      },
    });

    if (!user || !user.passwordAuth) {
      throw new UnauthorizedException('User not found');
    }

    // Hash new password
    const newPasswordHash = await bcrypt.hash(
      newPassword,
      this.bcryptSaltRounds,
    );

    // Update password
    await db
      .update(passwordAuth)
      .set({
        passwordHash: newPasswordHash,
        passwordChangedAt: new Date(),
      })
      .where(eq(passwordAuth.userId, user.id));

    // Mark token as used
    await db
      .update(passwordResetTokens)
      .set({
        usedAt: new Date(),
      })
      .where(eq(passwordResetTokens.id, resetToken.id));

    // Reset account lockout
    await db
      .update(users)
      .set({
        failedLoginAttempts: 0,
        isLocked: false,
        lockoutUntil: null,
      })
      .where(eq(users.id, user.id));

    // Log security event
    await this.securityService.logSecurityEvent({
      userId: user.id,
      eventType: 'password_reset',
      authMethod: 'password',
      ipAddress,
      userAgent,
      success: true,
    });

    return {
      message: 'Password reset successfully',
    };
  }

  private async handleFailedLogin(
    userId: string,
    ipAddress: string,
    userAgent: string,
  ) {
    const maxAttempts = this.configService.get('MAX_LOGIN_ATTEMPTS', {
      infer: true,
    });
    const lockoutDuration = this.configService.get('LOCKOUT_DURATION', {
      infer: true,
    });

    const user = await db.query.users.findFirst({
      where: eq(users.id, userId),
    });

    if (!user) return;

    const newFailedAttempts = (user.failedLoginAttempts || 0) + 1;
    const updateData: any = {
      failedLoginAttempts: newFailedAttempts,
    };

    if (newFailedAttempts >= maxAttempts) {
      updateData.isLocked = true;
      updateData.lockoutUntil = new Date(Date.now() + lockoutDuration);

      await this.securityService.logSecurityEvent({
        userId,
        eventType: 'account_locked',
        authMethod: 'password',
        ipAddress,
        userAgent,
        success: false,
        errorMessage: 'Account locked due to too many failed login attempts',
      });
    }

    await db.update(users).set(updateData).where(eq(users.id, userId));

    await this.securityService.logSecurityEvent({
      userId,
      eventType: 'login_failure',
      authMethod: 'password',
      ipAddress,
      userAgent,
      success: false,
      errorMessage: 'Invalid credentials',
    });
  }

  private isCommonPassword(password: string): boolean {
    // Simplified common password check
    const commonPasswords = [
      'password',
      '12345678',
      'password123',
      'qwerty',
      'admin123',
      'welcome',
      'letmein',
    ];
    return commonPasswords.includes(password.toLowerCase());
  }
}
