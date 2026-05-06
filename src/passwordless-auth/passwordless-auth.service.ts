import { AuthService } from '@/auth/auth.service';
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
import * as crypto from 'crypto';
import { and, eq, gt, isNull } from 'drizzle-orm';

@Injectable()
export class PasswordlessAuthService {
  constructor(
    private readonly configService: ConfigService<Env, true>,
    private readonly securityService: SecurityService,
    private readonly emailService: EmailService,
    private readonly authService: AuthService,
  ) {}

  async sendMagicLink(
    loginDto: PasswordlessLoginDto,
    ipAddress: string,
    userAgent: string,
  ) {
    const { email } = loginDto;

    const user = await db.query.users.findFirst({
      where: eq(users.email, email.toLowerCase()),
    });

    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(
      Date.now() +
        this.configService.get('MAGIC_LINK_EXPIRES_MS', { infer: true }),
    );

    await db.insert(magicLinkTokens).values({
      userId: user?.id ?? null,
      email: user ? null : email.toLowerCase(),
      token,
      expiresAt,
      ipAddress,
      userAgent,
    });

    const magicLink = `${this.configService.get('FRONTEND_URL', { infer: true })}/auth/passwordless/verify?token=${token}`;
    await this.emailService.sendMagicLink(email.toLowerCase(), magicLink);

    await this.securityService.logSecurityEvent({
      userId: user?.id ?? null,
      eventType: 'magic_link_sent',
      authMethod: 'passwordless',
      ipAddress,
      userAgent,
      success: true,
      metadata: user ? {} : { email: email.toLowerCase() },
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

    const { finalUser, isNewUser } = await db.transaction(async (tx) => {
      let userId = magicToken.userId;
      let finalUser = magicToken.user;
      let isNewUser = false;

      if (!userId && magicToken.email) {
        [finalUser] = await tx
          .insert(users)
          .values({
            email: magicToken.email,
            emailVerified: true,
          })
          .returning();

        userId = finalUser.id;
        isNewUser = true;
      } else if (userId) {
        [finalUser] = await tx
          .update(users)
          .set({
            emailVerified: true,
            lastLoginAt: new Date(),
            lastLoginIp: ipAddress,
          })
          .where(eq(users.id, userId))
          .returning();
      }

      await tx
        .update(magicLinkTokens)
        .set({ usedAt: new Date() })
        .where(eq(magicLinkTokens.id, magicToken.id));

      return { finalUser: finalUser!, isNewUser };
    });

    const tokens = await this.authService.generateTokens(
      finalUser.id,
      ipAddress,
      userAgent,
    );

    if (isNewUser) {
      await this.securityService.logSecurityEvent({
        userId: finalUser.id,
        eventType: 'registration',
        authMethod: 'passwordless',
        ipAddress,
        userAgent,
        success: true,
      });
    }

    await this.securityService.logSecurityEvent({
      userId: finalUser.id,
      eventType: 'magic_link_used',
      authMethod: 'passwordless',
      ipAddress,
      userAgent,
      success: true,
    });

    await this.securityService.logSecurityEvent({
      userId: finalUser.id,
      eventType: 'login_success',
      authMethod: 'passwordless',
      ipAddress,
      userAgent,
      success: true,
    });

    return {
      user: this.authService.sanitizeUser(finalUser),
      ...tokens,
    };
  }
}
