import { PasswordAuthService } from './password-auth.service';
import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { SecurityService } from '@/security/security.service';
import { EmailService } from '@/email/email.service';
import { AuthService } from '@/auth/auth.service';
import { db } from '@/db';
import * as bcrypt from 'bcrypt';
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
        passwordAuth: {
          findFirst: jest.fn(),
        },
        passwordResetTokens: {
          findFirst: jest.fn(),
        },
      },
    },
  };
});

jest.mock('bcrypt');

describe('PasswordAuthService', () => {
  let service: PasswordAuthService;

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        PasswordAuthService,
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((key: string) => {
              if (key === 'BCRYPT_SALT_ROUNDS') return 10;
              if (key === 'MAX_LOGIN_ATTEMPTS') return 5;
              if (key === 'LOCKOUT_DURATION') return 900000;
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
            sendPasswordResetEmail: jest.fn(),
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

    service = module.get<PasswordAuthService>(PasswordAuthService);
  });

  describe('bcrypt hashing and verification', () => {
    it('should hash password during registration', async () => {
      (db.query.users.findFirst as jest.Mock).mockResolvedValue(null);
      (bcrypt.hash as jest.Mock).mockResolvedValue('hashed-password');

      await service.register(
        {
          email: 'test@example.com',
          password: 'Password123!',
          firstName: 'John',
          lastName: 'Doe',
        },
        '127.0.0.1',
        'test-agent',
      );

      expect(bcrypt.hash).toHaveBeenCalledWith('Password123!', 10);
    });

    it('should verify password during login', async () => {
      const mockUser = {
        id: '1',
        email: 'test@example.com',
        passwordAuth: { passwordHash: 'hashed-password' },
        failedLoginAttempts: 0,
        isLocked: false,
      };
      (db.query.users.findFirst as jest.Mock).mockResolvedValue(mockUser);
      (bcrypt.compare as jest.Mock).mockResolvedValue(true);

      await service.login(
        {
          email: 'test@example.com',
          password: 'Password123!',
        },
        '127.0.0.1',
        'test-agent',
      );

      expect(bcrypt.compare).toHaveBeenCalledWith(
        'Password123!',
        'hashed-password',
      );
    });
  });

  describe('rate limiting (account lockout)', () => {
    it('should lock account after 5 failed attempts', async () => {
      const mockUser = {
        id: '1',
        email: 'test@example.com',
        passwordAuth: { passwordHash: 'hashed-password' },
        failedLoginAttempts: 4,
        isLocked: false,
      };
      (db.query.users.findFirst as jest.Mock).mockResolvedValue(mockUser);
      (bcrypt.compare as jest.Mock).mockResolvedValue(false);

      await expect(
        service.login(
          {
            email: 'test@example.com',
            password: 'WrongPassword',
          },
          '127.0.0.1',
          'test-agent',
        ),
      ).rejects.toThrow(UnauthorizedException);

      expect(db.update).toHaveBeenCalled();
      expect((db as any).set).toHaveBeenCalledWith(
        expect.objectContaining({
          isLocked: true,
          lockoutUntil: expect.any(Date),
        }),
      );
    });

    it('should prevent login if account is locked', async () => {
      const lockoutUntil = new Date(Date.now() + 100000);
      const mockUser = {
        id: '1',
        email: 'test@example.com',
        passwordAuth: { passwordHash: 'hashed-password' },
        failedLoginAttempts: 5,
        isLocked: true,
        lockoutUntil,
      };
      (db.query.users.findFirst as jest.Mock).mockResolvedValue(mockUser);

      await expect(
        service.login(
          {
            email: 'test@example.com',
            password: 'Password123!',
          },
          '127.0.0.1',
          'test-agent',
        ),
      ).rejects.toThrow(/Account is locked/);
    });
  });
});
