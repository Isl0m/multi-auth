import { WebAuthnAuthService } from './webauthn-auth.service';
import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { SecurityService } from '@/security/security.service';
import { AuthService } from '@/auth/auth.service';
import { EmailService } from '@/email/email.service';
import { UnauthorizedException } from '@nestjs/common';
import { db } from '@/db';

jest.mock('@/db', () => ({
  db: {
    insert: jest.fn().mockReturnThis(),
    values: jest.fn().mockResolvedValue([{ id: '1' }]),
    delete: jest.fn().mockReturnThis(),
    where: jest.fn().mockResolvedValue({}),
    query: {
      users: {
        findFirst: jest.fn(),
      },
      webauthnCredentials: {
        findMany: jest.fn(),
      },
      webauthnRegistrationTokens: {
        findFirst: jest.fn(),
      },
    },
  },
}));

describe('WebAuthnAuthService', () => {
  let service: WebAuthnAuthService;
  let emailService: EmailService;

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        WebAuthnAuthService,
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((key: string) => {
              if (key === 'WEBAUTHN_RP_NAME') return 'Test RP';
              if (key === 'WEBAUTHN_RP_ID') return 'localhost';
              if (key === 'WEBAUTHN_ORIGIN') return 'http://localhost:3000';
              if (key === 'FRONTEND_URL') return 'http://localhost:3000';
              return null;
            }),
          },
        },
        {
          provide: SecurityService,
          useValue: {
            logSecurityEvent: jest.fn(),
          },
        },
        {
          provide: AuthService,
          useValue: {
            generateTokens: jest
              .fn()
              .mockResolvedValue({ accessToken: 'at', refreshToken: 'rt' }),
            sanitizeUser: jest.fn().mockImplementation((u) => u),
          },
        },
        {
          provide: EmailService,
          useValue: {
            sendWebAuthnRegistrationEmail: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<WebAuthnAuthService>(WebAuthnAuthService);
    emailService = module.get<EmailService>(EmailService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('sendRegistrationEmail', () => {
    it('should send a registration email when user does not exist', async () => {
      (db.query.users.findFirst as jest.Mock).mockResolvedValue(null);

      const result = await service.sendRegistrationEmail(
        'new@example.com',
        '127.0.0.1',
        'test-agent',
      );

      expect(result.message).toContain('email sent');
      expect(db.insert).toHaveBeenCalled();
      expect(emailService.sendWebAuthnRegistrationEmail).toHaveBeenCalledWith(
        'new@example.com',
        expect.stringContaining('token='),
      );
    });

    it('should send registration email even when user already exists (adding passkey to existing account)', async () => {
      (db.query.users.findFirst as jest.Mock).mockResolvedValue({
        id: '1',
        email: 'existing@example.com',
      });

      const result = await service.sendRegistrationEmail(
        'existing@example.com',
        '127.0.0.1',
        'test-agent',
      );

      expect(result.message).toContain('email sent');
      expect(emailService.sendWebAuthnRegistrationEmail).toHaveBeenCalledWith(
        'existing@example.com',
        expect.stringContaining('token='),
      );
    });

    it('should normalise email to lowercase before lookup', async () => {
      (db.query.users.findFirst as jest.Mock).mockResolvedValue(null);

      await service.sendRegistrationEmail(
        'New@Example.COM',
        '127.0.0.1',
        'test-agent',
      );

      expect(emailService.sendWebAuthnRegistrationEmail).toHaveBeenCalledWith(
        'new@example.com',
        expect.any(String),
      );
    });
  });

  describe('generateAuthenticationOptions', () => {
    it('should throw UnauthorizedException when user has no credentials', async () => {
      (db.query.users.findFirst as jest.Mock).mockResolvedValue({
        id: '1',
        email: 'test@example.com',
        webauthnCredentials: [],
      });

      await expect(
        service.generateAuthenticationOptions('test@example.com'),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should throw UnauthorizedException when user does not exist', async () => {
      (db.query.users.findFirst as jest.Mock).mockResolvedValue(null);

      await expect(
        service.generateAuthenticationOptions('nobody@example.com'),
      ).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('getUserCredentials', () => {
    it('should return the credentials list for a user', async () => {
      const mockCreds = [
        { id: 'cred-1', deviceName: 'iPhone', lastUsedAt: new Date() },
      ];
      (db.query.webauthnCredentials.findMany as jest.Mock).mockResolvedValue(
        mockCreds,
      );

      const result = await service.getUserCredentials('user-1');

      expect(result).toBe(mockCreds);
      expect(db.query.webauthnCredentials.findMany).toHaveBeenCalledWith(
        expect.objectContaining({ where: expect.anything() }),
      );
    });
  });

  describe('deleteCredential', () => {
    it('should delete a credential and return a confirmation message', async () => {
      const result = await service.deleteCredential('user-1', 'cred-1');

      expect(result.message).toContain('deleted');
      expect(db.delete).toHaveBeenCalled();
    });
  });
});
