import { Env } from '@/config/configuration';
import { db } from '@/db';
import { users, webauthnCredentials } from '@/db/schema';
import { SecurityService } from '@/security/security.service';
import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
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
import { and, eq } from 'drizzle-orm';

@Injectable()
export class WebAuthnService {
  private readonly rpName: string;
  private readonly rpId: string;
  private readonly origin: string;

  constructor(
    private readonly configService: ConfigService<Env, true>,
    private readonly jwtService: JwtService,
    private readonly securityService: SecurityService,
  ) {
    this.rpName = this.configService.get('WEBAUTHN_RP_NAME', { infer: true });
    this.rpId = this.configService.get('WEBAUTHN_RP_ID', { infer: true });
    this.origin = this.configService.get('WEBAUTHN_ORIGIN', { infer: true });
  }

  async generateRegistrationOptions(userId: string) {
    const user = await db.query.users.findFirst({
      where: eq(users.id, userId),
      with: {
        webauthnCredentials: true,
      },
    });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    const excludeCredentials = user.webauthnCredentials.map((cred) => ({
      id: cred.credentialId,
      type: 'public-key' as const,
      transports: cred.transports as AuthenticatorTransport[] | undefined,
    }));

    const options = await generateRegistrationOptions({
      rpName: this.rpName,
      rpID: this.rpId,
      userID: isoUint8Array.fromUTF8String(user.id),
      userName: user.email,
      userDisplayName:
        `${user.firstName || ''} ${user.lastName || ''}`.trim() || user.email,
      timeout: 60000,
      attestationType: 'none',
      excludeCredentials,
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
      },
    });

    return options;
  }

  async verifyRegistration(
    userId: string,
    credential: RegistrationResponseJSON,
    expectedChallenge: string,
    deviceName?: string,
    ipAddress?: string,
    userAgent?: string,
  ) {
    const user = await db.query.users.findFirst({
      where: eq(users.id, userId),
    });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    try {
      const verification = await verifyRegistrationResponse({
        response: credential,
        // expectedChallenge: credential.response.clientDataJSON,
        expectedChallenge,
        expectedOrigin: this.origin,
        expectedRPID: this.rpId,
      });

      if (!verification.verified || !verification.registrationInfo) {
        throw new BadRequestException('Verification failed');
      }

      // Save credential
      await db.insert(webauthnCredentials).values({
        userId: user.id,
        credentialId: verification.registrationInfo.credential.id,
        credentialPublicKey: isoUint8Array.toUTF8String(
          verification.registrationInfo.credential.publicKey,
        ),
        counter: verification.registrationInfo.credential.counter,
        deviceName: deviceName || 'Unknown Device',
        lastUsedAt: new Date(),
      });

      // Log event
      await this.securityService.logSecurityEvent({
        userId: user.id,
        eventType: 'webauthn_registered',
        authMethod: 'webauthn',
        ipAddress,
        userAgent,
        success: true,
      });

      return {
        verified: true,
        message: 'WebAuthn credential registered successfully',
      };
    } catch (error) {
      await this.securityService.logSecurityEvent({
        userId: user.id,
        eventType: 'webauthn_registered',
        authMethod: 'webauthn',
        ipAddress,
        userAgent,
        success: false,
        errorMessage: error.message,
      });
      throw new BadRequestException('Failed to verify registration');
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
      transports: cred.transports as AuthenticatorTransport[] | undefined,
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

    const credentialId = Buffer.from(credential.id, 'base64url').toString(
      'base64',
    );
    const dbCredential = user.webauthnCredentials.find(
      (cred) => cred.credentialId === credentialId,
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
        expectedChallenge: credential.response.clientDataJSON,
        expectedOrigin: this.origin,
        expectedRPID: this.rpId,
        credential: {
          id: dbCredential.credentialId,
          publicKey: isoUint8Array.fromUTF8String(
            dbCredential.credentialPublicKey,
          ),
          counter: dbCredential.counter,
        },
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

      await this.securityService.logSecurityEvent({
        userId: user.id,
        eventType: 'webauthn_authenticated',
        authMethod: 'webauthn',
        ipAddress,
        userAgent,
        success: true,
      });

      // Generate JWT token
      const token = this.generateToken(user.id);

      return {
        verified: true,
        user: this.sanitizeUser(user),
        token,
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

  private generateToken(userId: string): string {
    const payload = { sub: userId };
    return this.jwtService.sign(payload, {
      secret: this.configService.get('JWT_SECRET', { infer: true }),
      expiresIn: this.configService.get('JWT_EXPIRES_IN', { infer: true }),
    });
  }

  private sanitizeUser(user: any) {
    const { passwordAuth, webauthnCredentials, ...sanitized } = user;
    return sanitized;
  }
}
