import { AuthService } from './auth.service';
import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { UnauthorizedException } from '@nestjs/common';
import { db } from '@/db';

jest.mock('@/db', () => ({
  db: {
    insert: jest.fn().mockReturnThis(),
    values: jest.fn().mockResolvedValue([{ id: '1' }]),
    update: jest.fn().mockReturnThis(),
    set: jest.fn().mockReturnThis(),
    where: jest.fn().mockResolvedValue({}),
    query: {
      refreshTokens: {
        findFirst: jest.fn(),
      },
    },
  },
}));

describe('AuthService', () => {
  let service: AuthService;
  let jwtService: JwtService;

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((key: string) => {
              if (key === 'JWT_SECRET') return 'test-secret';
              if (key === 'JWT_EXPIRES_IN') return '1h';
              return null;
            }),
          },
        },
        {
          provide: JwtService,
          useValue: {
            sign: jest.fn().mockReturnValue('test-token'),
          },
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    jwtService = module.get<JwtService>(JwtService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('generateTokens', () => {
    it('should generate access and refresh tokens', async () => {
      const userId = 'user-1';
      const tokens = await service.generateTokens(
        userId,
        '127.0.0.1',
        'test-agent',
      );

      expect(tokens).toEqual({
        accessToken: 'test-token',
        refreshToken: expect.any(String),
      });
      expect(jwtService.sign).toHaveBeenCalledWith(
        { sub: userId },
        expect.objectContaining({ secret: 'test-secret' }),
      );
      expect(db.insert).toHaveBeenCalled();
    });
  });

  describe('refreshAccessToken', () => {
    const validRecord = {
      id: 'rt-1',
      userId: 'user-1',
      token: 'valid-token',
      isRevoked: false,
      expiresAt: new Date(Date.now() + 60_000),
      user: { id: 'user-1', email: 'test@example.com' },
    };

    it('should revoke the old token and return new tokens for a valid refresh token', async () => {
      (db.query.refreshTokens.findFirst as jest.Mock).mockResolvedValue(
        validRecord,
      );

      const result = await service.refreshAccessToken(
        'valid-token',
        '127.0.0.1',
        'agent',
      );

      expect(result).toEqual({
        accessToken: 'test-token',
        refreshToken: expect.any(String),
      });
      expect(db.update).toHaveBeenCalled();
      expect((db as any).set).toHaveBeenCalledWith({ isRevoked: true });
    });

    it('should throw UnauthorizedException when token is not found', async () => {
      (db.query.refreshTokens.findFirst as jest.Mock).mockResolvedValue(null);

      await expect(
        service.refreshAccessToken('bad-token', '127.0.0.1', 'agent'),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should throw UnauthorizedException when token is revoked', async () => {
      (db.query.refreshTokens.findFirst as jest.Mock).mockResolvedValue({
        ...validRecord,
        isRevoked: true,
      });

      await expect(
        service.refreshAccessToken('revoked-token', '127.0.0.1', 'agent'),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should throw UnauthorizedException when token is expired', async () => {
      (db.query.refreshTokens.findFirst as jest.Mock).mockResolvedValue({
        ...validRecord,
        expiresAt: new Date(Date.now() - 1000),
      });

      await expect(
        service.refreshAccessToken('expired-token', '127.0.0.1', 'agent'),
      ).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('logLogout', () => {
    it('should insert a logout security event', async () => {
      await service.logLogout('user-1', '127.0.0.1', 'test-agent');

      expect(db.insert).toHaveBeenCalled();
      expect((db as any).values).toHaveBeenCalledWith(
        expect.objectContaining({
          eventType: 'logout',
          userId: 'user-1',
          success: true,
        }),
      );
    });
  });

  describe('sanitizeUser', () => {
    it('should remove passwordAuth from user object', () => {
      const user = {
        id: '1',
        email: 'test@example.com',
        passwordAuth: { passwordHash: 'hashed' },
      };
      const sanitized = service.sanitizeUser(user);
      expect(sanitized).not.toHaveProperty('passwordAuth');
      expect(sanitized.email).toBe('test@example.com');
    });
  });
});
