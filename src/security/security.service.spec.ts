import { SecurityService } from './security.service';
import { Test, TestingModule } from '@nestjs/testing';
import { db } from '@/db';

jest.mock('@/db', () => ({
  db: {
    insert: jest.fn().mockReturnThis(),
    values: jest.fn().mockResolvedValue({}),
    query: {
      securityEvents: {
        findMany: jest.fn(),
      },
    },
  },
}));

describe('SecurityService', () => {
  let service: SecurityService;

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [SecurityService],
    }).compile();

    service = module.get<SecurityService>(SecurityService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('logSecurityEvent', () => {
    it('should insert a security event into the database', async () => {
      const event = {
        userId: '1',
        eventType: 'login_success' as const,
        authMethod: 'password' as const,
        ipAddress: '127.0.0.1',
        userAgent: 'test-agent',
        success: true,
      };

      await service.logSecurityEvent(event);

      expect(db.insert).toHaveBeenCalled();
      expect((db as any).values).toHaveBeenCalledWith(event);
    });
  });

  describe('getUserSecurityEvents', () => {
    it('should return security events for a user with default limit', async () => {
      const mockEvents = [{ id: '1', eventType: 'login_success' }];
      (db.query.securityEvents.findMany as jest.Mock).mockResolvedValue(
        mockEvents,
      );

      const result = await service.getUserSecurityEvents('user-1');

      expect(result).toBe(mockEvents);
      expect(db.query.securityEvents.findMany).toHaveBeenCalledWith(
        expect.objectContaining({ where: expect.anything(), limit: 50 }),
      );
    });

    it('should pass a custom limit to the query', async () => {
      (db.query.securityEvents.findMany as jest.Mock).mockResolvedValue([]);

      await service.getUserSecurityEvents('user-1', 10);

      expect(db.query.securityEvents.findMany).toHaveBeenCalledWith(
        expect.objectContaining({ limit: 10 }),
      );
    });
  });

  describe('getSecurityMetrics', () => {
    it('should compute login success rate from recent events', async () => {
      (db.query.securityEvents.findMany as jest.Mock).mockResolvedValue([
        { eventType: 'login_success' },
        { eventType: 'login_success' },
        { eventType: 'login_failure' },
        { eventType: 'registration' },
      ]);

      const metrics = await service.getSecurityMetrics();

      expect(metrics.totalEvents).toBe(4);
      expect(metrics.successfulLogins).toBe(2);
      expect(metrics.failedLogins).toBe(1);
      expect(metrics.registrations).toBe(1);
      expect(metrics.loginSuccessRate).toBeCloseTo(66.67, 1);
    });

    it('should return 0 success rate when there are no login events', async () => {
      (db.query.securityEvents.findMany as jest.Mock).mockResolvedValue([]);

      const metrics = await service.getSecurityMetrics();

      expect(metrics.loginSuccessRate).toBe(0);
      expect(metrics.totalEvents).toBe(0);
    });
  });
});
