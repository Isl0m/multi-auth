import { AuthService } from '@/auth/auth.service';
import { Env } from '@/config/configuration';
import { db } from '@/db';
import {
  users,
  webauthnCredentials,
  webauthnRegistrationTokens,
} from '@/db/schema';
import { EmailService } from '@/email/email.service';
import { SecurityService } from '@/security/security.service';
import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type {
  AuthenticationResponseJSON,
  RegistrationResponseJSON,
} from '@simplewebauthn/server';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import { isoUint8Array } from '@simplewebauthn/server/helpers';
import * as crypto from 'crypto';
import { and, eq, gt, isNull } from 'drizzle-orm';

@Injectable()
export class WebAuthnAuthService {
  private readonly rpName: string;
  private readonly rpId: string;
  private readonly origin: string;

  constructor(
    private readonly configService: ConfigService<Env, true>,
    private readonly securityService: SecurityService,
    private readonly authService: AuthService,
    private readonly emailService: EmailService,
  ) {
    this.rpName = this.configService.get('WEBAUTHN_RP_NAME', { infer: true });
    this.rpId = this.configService.get('WEBAUTHN_RP_ID', { infer: true });
    this.origin = this.configService.get('WEBAUTHN_ORIGIN', { infer: true });
  }

  async sendRegistrationEmail(
    email: string,
    ipAddress: string,
    userAgent: string,
  ) {
    const normalizedEmail = email.toLowerCase();

    // Check if user already exists
    const existingUser = await db.query.users.findFirst({
      where: eq(users.email, normalizedEmail),
    });

    if (existingUser) {
      throw new BadRequestException(
        'User already exists. Please login instead.',
      );
    }

    // Generate registration token
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

    // Save token
    await db.insert(webauthnRegistrationTokens).values({
      email: normalizedEmail,
      token,
      expiresAt,
      ipAddress,
      userAgent,
    });

    // Send registration email
    const registrationUrl = `${this.configService.get('FRONTEND_URL', { infer: true })}/auth/webauthn/register?token=${token}`;
    await this.emailService.sendWebAuthnRegistrationEmail(
      normalizedEmail,
      registrationUrl,
    );

    return {
      message: 'Verification email sent. Please check your inbox.',
    };
  }

  async generateRegistrationOptions(token: string) {
    // Find valid token
    const regToken = await db.query.webauthnRegistrationTokens.findFirst({
      where: and(
        eq(webauthnRegistrationTokens.token, token),
        isNull(webauthnRegistrationTokens.usedAt),
        gt(webauthnRegistrationTokens.expiresAt, new Date()),
      ),
    });

    if (!regToken) {
      throw new BadRequestException('Invalid or expired registration token');
    }

    const options = await generateRegistrationOptions({
      rpName: this.rpName,
      rpID: this.rpId,
      userID: isoUint8Array.fromUTF8String(regToken.email),
      userName: regToken.email,
      userDisplayName: regToken.email,
      timeout: 60000,
      attestationType: 'none',
      excludeCredentials: [],
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
      },
    });

    return options;
  }

  async verifyRegistration(
    token: string,
    credential: RegistrationResponseJSON,
    expectedChallenge: string,
    deviceName?: string,
    ipAddress?: string,
    userAgent?: string,
  ) {
    // Find valid token
    const regToken = await db.query.webauthnRegistrationTokens.findFirst({
      where: and(
        eq(webauthnRegistrationTokens.token, token),
        isNull(webauthnRegistrationTokens.usedAt),
        gt(webauthnRegistrationTokens.expiresAt, new Date()),
      ),
    });

    if (!regToken) {
      throw new BadRequestException('Invalid or expired registration token');
    }

    try {
      const verification = await verifyRegistrationResponse({
        response: credential,
        expectedChallenge,
        expectedOrigin: this.origin,
        expectedRPID: this.rpId,
        requireUserVerification: false,
      });
      if (!verification.verified || !verification.registrationInfo) {
        throw new BadRequestException('Verification failed');
      }
      const result = await db.transaction(async (tx) => {
        // 1. Create the user
        const [newUser] = await tx
          .insert(users)
          .values({
            email: regToken.email,
            emailVerified: true,
          })
          .returning();

        // 2. Save credential
        await tx.insert(webauthnCredentials).values({
          userId: newUser.id,
          credentialId: verification.registrationInfo!.credential.id,
          credentialPublicKey: Buffer.from(
            verification.registrationInfo!.credential.publicKey,
          ).toString('base64'),
          counter: verification.registrationInfo!.credential.counter,
          deviceName: deviceName || 'Unknown Device',
          lastUsedAt: new Date(),
        });

        // 3. Mark token as used
        await tx
          .update(webauthnRegistrationTokens)
          .set({ usedAt: new Date() })
          .where(eq(webauthnRegistrationTokens.id, regToken.id));

        return newUser;
      });

      // 4. Log event
      await this.securityService.logSecurityEvent({
        userId: result.id,
        eventType: 'webauthn_registered',
        authMethod: 'webauthn',
        ipAddress: ipAddress ?? null,
        userAgent: userAgent ?? null,
        success: true,
      });

      const tokens = await this.authService.generateTokens(
        result.id,
        ipAddress,
        userAgent,
      );

      return {
        verified: true,
        ...tokens,
        user: this.authService.sanitizeUser(result),
      };
    } catch (error) {
      console.error('WebAuthn Registration Error:', error);
      throw new BadRequestException(error.message);
    }
  }

  async generateAuthenticationOptions(email: string) {
    const user = await db.query.users.findFirst({
      where: eq(users.email, email.toLowerCase()),
      with: {
        webauthnCredentials: true,
      },
    });

    if (!user || user.webauthnCredentials.length === 0) {
      throw new UnauthorizedException('No credentials found for this user');
    }

    const allowCredentials = user.webauthnCredentials.map((cred) => ({
      id: cred.credentialId,
      type: 'public-key' as const,
      transports: (cred.transports as AuthenticatorTransport[]) || undefined,
    }));

    const options = await generateAuthenticationOptions({
      rpID: this.rpId,
      timeout: 60000,
      allowCredentials,
      userVerification: 'preferred',
    });

    return { ...options, userId: user.id };
  }

  async verifyAuthentication(
    userId: string,
    credential: AuthenticationResponseJSON,
    expectedChallenge: string,
    ipAddress: string,
    userAgent: string,
  ) {
    const user = await db.query.users.findFirst({
      where: eq(users.id, userId),
      with: {
        webauthnCredentials: true,
      },
    });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    const dbCredential = user.webauthnCredentials.find(
      (cred) => cred.credentialId === credential.id,
    );

    if (!dbCredential) {
      await this.securityService.logSecurityEvent({
        userId: user.id,
        eventType: 'login_failure',
        authMethod: 'webauthn',
        ipAddress,
        userAgent,
        success: false,
        errorMessage: 'Credential not found',
      });
      throw new UnauthorizedException('Credential not found');
    }

    try {
      const verification = await verifyAuthenticationResponse({
        response: credential,
        expectedChallenge,
        expectedOrigin: this.origin,
        expectedRPID: this.rpId,
        credential: {
          id: dbCredential.credentialId,
          publicKey: Buffer.from(dbCredential.credentialPublicKey, 'base64'),
          counter: dbCredential.counter,
        },
        requireUserVerification: false,
      });

      if (!verification.verified) {
        throw new UnauthorizedException('Verification failed');
      }

      // Update credential counter and last used
      await db
        .update(webauthnCredentials)
        .set({
          counter: verification.authenticationInfo.newCounter,
          lastUsedAt: new Date(),
        })
        .where(eq(webauthnCredentials.id, dbCredential.id));

      // Update user last login
      await db
        .update(users)
        .set({
          lastLoginAt: new Date(),
          lastLoginIp: ipAddress,
        })
        .where(eq(users.id, user.id));

      // Log successful authentication
      await this.securityService.logSecurityEvent({
        userId: user.id,
        eventType: 'login_success',
        authMethod: 'webauthn',
        ipAddress,
        userAgent,
        success: true,
      });

      const tokens = await this.authService.generateTokens(
        user.id,
        ipAddress,
        userAgent,
      );

      return {
        verified: true,
        user: this.authService.sanitizeUser(user),
        ...tokens,
      };
    } catch (error) {
      await this.securityService.logSecurityEvent({
        userId: user.id,
        eventType: 'login_failure',
        authMethod: 'webauthn',
        ipAddress,
        userAgent,
        success: false,
        errorMessage: error.message,
      });
      throw new UnauthorizedException('Authentication failed');
    }
  }

  async getUserCredentials(userId: string) {
    return db.query.webauthnCredentials.findMany({
      where: eq(webauthnCredentials.userId, userId),
      columns: {
        id: true,
        deviceName: true,
        credentialDeviceType: true,
        lastUsedAt: true,
        createdAt: true,
      },
    });
  }

  async deleteCredential(userId: string, credentialId: string) {
    await db
      .delete(webauthnCredentials)
      .where(
        and(
          eq(webauthnCredentials.id, credentialId),
          eq(webauthnCredentials.userId, userId),
        ),
      );

    return { message: 'Credential deleted successfully' };
  }
}
