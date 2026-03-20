import { Env } from '@/config/configuration';
import { db } from '@/db';
import { refreshTokens, users } from '@/db/schema';
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
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

    await db.insert(refreshTokens).values({
      userId,
      token: refreshToken,
      expiresAt,
      ipAddress,
      userAgent,
    });

    return { accessToken, refreshToken };
  }

  async refreshAccessToken(token: string, ipAddress?: string, userAgent?: string) {
    const refreshTokenRecord = await db.query.refreshTokens.findFirst({
      where: eq(refreshTokens.token, token),
      with: { user: true },
    });

    if (
      !refreshTokenRecord ||
      refreshTokenRecord.isRevoked ||
      refreshTokenRecord.expiresAt < new Date()
    ) {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }

    // Revoke old token
    await db
      .update(refreshTokens)
      .set({ isRevoked: true })
      .where(eq(refreshTokens.id, refreshTokenRecord.id));

    // Generate new tokens
    return this.generateTokens(refreshTokenRecord.userId, ipAddress, userAgent);
  }

  sanitizeUser(user: any) {
    const { passwordAuth, ...sanitized } = user;
    return sanitized;
  }
}
