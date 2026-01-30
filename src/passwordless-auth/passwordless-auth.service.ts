import {
  PasswordlessLoginDto,
  VerifyMagicLinkDto,
} from '@/common/dto/auth.dto';
import { Env } from '@/config/configuration';
import { db } from '@/db';
import { magicLinkTokens, users } from '@/db/schema';
import { EmailService } from '@/email/email.service';
import { SecurityService } from '@/security/security.service';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as crypto from 'crypto';
import { and, eq, gt, isNull } from 'drizzle-orm';

@Injectable()
export class PasswordlessAuthService {
  constructor(
    private readonly configService: ConfigService<Env, true>,
    private readonly jwtService: JwtService,
    private readonly securityService: SecurityService,
    private readonly emailService: EmailService,
  ) {}

  async sendMagicLink(
    loginDto: PasswordlessLoginDto,
    ipAddress: string,
    userAgent: string,
  ) {
    const { email } = loginDto;

    // Find or create user
    let user = await db.query.users.findFirst({
      where: eq(users.email, email.toLowerCase()),
    });

    if (!user) {
      // Create new user for passwordless auth
      [user] = await db
        .insert(users)
        .values({
          email: email.toLowerCase(),
          emailVerified: true,
        })
        .returning();

      await this.securityService.logSecurityEvent({
        userId: user.id,
        eventType: 'registration',
        authMethod: 'passwordless',
        ipAddress,
        userAgent,
        success: true,
      });
    }

    // Generate magic link token
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

    // Save token
    await db.insert(magicLinkTokens).values({
      userId: user.id,
      token,
      expiresAt,
      ipAddress,
      userAgent,
    });

    // Send magic link email
    const magicLink = `${this.configService.get('FRONTEND_URL', { infer: true })}/auth/passwordless/verify?token=${token}`;
    await this.emailService.sendMagicLink(user.email, magicLink);

    // Log event
    await this.securityService.logSecurityEvent({
      userId: user.id,
      eventType: 'magic_link_sent',
      authMethod: 'passwordless',
      ipAddress,
      userAgent,
      success: true,
    });

    return {
      message: 'Magic link sent to your email',
    };
  }

  async verifyMagicLink(
    verifyDto: VerifyMagicLinkDto,
    ipAddress: string,
    userAgent: string,
  ) {
    const { token } = verifyDto;

    // Find valid token
    const magicToken = await db.query.magicLinkTokens.findFirst({
      where: and(
        eq(magicLinkTokens.token, token),
        isNull(magicLinkTokens.usedAt),
        gt(magicLinkTokens.expiresAt, new Date()),
      ),
      with: {
        user: true,
      },
    });

    if (!magicToken) {
      await this.securityService.logSecurityEvent({
        userId: null,
        eventType: 'login_failure',
        authMethod: 'passwordless',
        ipAddress,
        userAgent,
        success: false,
        errorMessage: 'Invalid or expired magic link',
      });
      throw new UnauthorizedException('Invalid or expired magic link');
    }

    // Mark token as used
    await db
      .update(magicLinkTokens)
      .set({ usedAt: new Date() })
      .where(eq(magicLinkTokens.id, magicToken.id));

    // Update user last login
    await db
      .update(users)
      .set({
        lastLoginAt: new Date(),
        lastLoginIp: ipAddress,
      })
      .where(eq(users.id, magicToken.userId));

    // Log successful login
    await this.securityService.logSecurityEvent({
      userId: magicToken.userId,
      eventType: 'login_success',
      authMethod: 'passwordless',
      ipAddress,
      userAgent,
      success: true,
    });

    // Log magic link used
    await this.securityService.logSecurityEvent({
      userId: magicToken.userId,
      eventType: 'magic_link_used',
      authMethod: 'passwordless',
      ipAddress,
      userAgent,
      success: true,
    });

    // Generate JWT token
    const jwtToken = this.generateToken(magicToken.userId);

    return {
      user: this.sanitizeUser(magicToken.user),
      token: jwtToken,
    };
  }

  private generateToken(userId: string): string {
    const payload = { sub: userId };
    return this.jwtService.sign(payload, {
      secret: this.configService.get('JWT_SECRET', { infer: true }),
      expiresIn: this.configService.get('JWT_EXPIRES_IN', { infer: true }),
    });
  }

  private sanitizeUser(user: any) {
    const { passwordAuth, ...sanitized } = user;
    return sanitized;
  }
}
