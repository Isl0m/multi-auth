import { PasswordlessAuthService } from './passwordless-auth.service';
import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { SecurityService } from '@/security/security.service';
import { EmailService } from '@/email/email.service';
import { AuthService } from '@/auth/auth.service';
import { db } from '@/db';
import { UnauthorizedException } from '@nestjs/common';

jest.mock('@/db', () => {
  const mockTx = {
    insert: jest.fn().mockReturnThis(),
    values: jest.fn().mockReturnThis(),
    returning: jest.fn().mockResolvedValue([{ id: '1' }]),
    update: jest.fn().mockReturnThis(),
    set: jest.fn().mockReturnThis(),
    where: jest.fn().mockReturnThis(),
  };
  return {
    db: {
      insert: jest.fn().mockReturnThis(),
      values: jest.fn().mockReturnThis(),
      returning: jest.fn().mockResolvedValue([{ id: '1' }]),
      update: jest.fn().mockReturnThis(),
      set: jest.fn().mockReturnThis(),
      where: jest.fn().mockReturnThis(),
      transaction: jest.fn().mockImplementation(async (cb) => cb(mockTx)),
      query: {
        users: {
          findFirst: jest.fn(),
        },
        magicLinkTokens: {
          findFirst: jest.fn(),
        },
      },
    },
  };
});

describe('PasswordlessAuthService', () => {
  let service: PasswordlessAuthService;
  let emailService: EmailService;

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        PasswordlessAuthService,
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((key: string) => {
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
          provide: EmailService,
          useValue: {
            sendMagicLink: jest.fn(),
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
      ],
    }).compile();

    service = module.get<PasswordlessAuthService>(PasswordlessAuthService);
    emailService = module.get<EmailService>(EmailService);
  });

  describe('magic link token generation', () => {
    it('should generate a token and send an email', async () => {
      (db.query.users.findFirst as jest.Mock).mockResolvedValue({
        id: '1',
        email: 'test@example.com',
      });

      await service.sendMagicLink(
        { email: 'test@example.com' },
        '127.0.0.1',
        'test-agent',
      );

      expect(db.insert).toHaveBeenCalled();
      expect(emailService.sendMagicLink).toHaveBeenCalledWith(
        'test@example.com',
        expect.stringContaining('token='),
      );
    });
  });

  describe('magic link single-use enforcement and expiry', () => {
    it('should verify token and mark it as used', async () => {
      const mockToken = {
        id: '1',
        token: 'valid-token',
        userId: '1',
        expiresAt: new Date(Date.now() + 10000),
        usedAt: null,
        user: { id: '1', email: 'test@example.com' },
      };
      (db.query.magicLinkTokens.findFirst as jest.Mock).mockResolvedValue(
        mockToken,
      );

      const result = await service.verifyMagicLink(
        { token: 'valid-token' },
        '127.0.0.1',
        'test-agent',
      );

      expect(result).toHaveProperty('accessToken');
    });

    it('should throw UnauthorizedException if token is already used', async () => {
      (db.query.magicLinkTokens.findFirst as jest.Mock).mockResolvedValue(null);

      await expect(
        service.verifyMagicLink(
          { token: 'used-token' },
          '127.0.0.1',
          'test-agent',
        ),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should throw UnauthorizedException if token is expired', async () => {
      (db.query.magicLinkTokens.findFirst as jest.Mock).mockResolvedValue(null);

      await expect(
        service.verifyMagicLink(
          { token: 'expired-token' },
          '127.0.0.1',
          'test-agent',
        ),
      ).rejects.toThrow(UnauthorizedException);
    });
  });
});
