import { Env } from '@/config/configuration';
import { db } from '@/db';
import { refreshTokens, securityEvents } from '@/db/schema';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as crypto from 'crypto';
import { eq } from 'drizzle-orm';

@Injectable()
export class AuthService {
  constructor(
    private readonly configService: ConfigService<Env, true>,
    private readonly jwtService: JwtService,
  ) {}

  async generateTokens(userId: string, ipAddress?: string, userAgent?: string) {
    const accessToken = this.jwtService.sign(
      { sub: userId },
      {
        secret: this.configService.get('JWT_SECRET', { infer: true }),
        expiresIn: this.configService.get('JWT_EXPIRES_IN', { infer: true }),
      },
    );

    const refreshToken = crypto.randomBytes(64).toString('hex');
    const expiresAt = new Date(
      Date.now() +
        this.configService.get('REFRESH_TOKEN_EXPIRES_MS', { infer: true }),
    );

    await db.insert(refreshTokens).values({
      userId,
      token: refreshToken,
      expiresAt,
      ipAddress,
      userAgent,
    });

    return { accessToken, refreshToken };
  }

  async refreshAccessToken(
    token: string,
    ipAddress?: string,
    userAgent?: string,
  ) {
    const refreshTokenRecord = await db.query.refreshTokens.findFirst({
      where: eq(refreshTokens.token, token),
      with: { user: true },
    });

    if (
      !refreshTokenRecord ||
      refreshTokenRecord.isRevoked ||
      refreshTokenRecord.expiresAt < new Date()
    ) {
      await db.insert(securityEvents).values({
        userId: refreshTokenRecord?.userId ?? null,
        eventType: 'login_failure',
        authMethod: null,
        ipAddress: ipAddress ?? null,
        userAgent: userAgent ?? null,
        success: false,
        errorMessage: 'Invalid or expired refresh token',
      });
      throw new UnauthorizedException('Invalid or expired refresh token');
    }

    await db
      .update(refreshTokens)
      .set({ isRevoked: true })
      .where(eq(refreshTokens.id, refreshTokenRecord.id));

    return this.generateTokens(refreshTokenRecord.userId, ipAddress, userAgent);
  }

  async logLogout(userId: string, ipAddress?: string, userAgent?: string) {
    await db.insert(securityEvents).values({
      userId,
      eventType: 'logout',
      authMethod: null,
      ipAddress: ipAddress ?? null,
      userAgent: userAgent ?? null,
      success: true,
      errorMessage: null,
    });
  }

  sanitizeUser(user: any) {
    const { passwordAuth: _passwordAuth, ...sanitized } = user;
    return sanitized;
  }
}
