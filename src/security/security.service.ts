import { db } from '@/db';
import { NewSecurityEvent, securityEvents } from '@/db/schema';
import { Injectable } from '@nestjs/common';
import { desc, eq, gte } from 'drizzle-orm';

@Injectable()
export class SecurityService {
  async logSecurityEvent(event: Omit<NewSecurityEvent, 'id' | 'createdAt'>) {
    await db.insert(securityEvents).values(event);
  }

  async getUserSecurityEvents(userId: string, limit: number = 50) {
    return db.query.securityEvents.findMany({
      where: eq(securityEvents.userId, userId),
      orderBy: [desc(securityEvents.createdAt)],
      limit,
    });
  }

  async getAllSecurityEvents(limit: number = 100) {
    return db.query.securityEvents.findMany({
      orderBy: [desc(securityEvents.createdAt)],
      limit,
      with: {
        user: {
          columns: {
            id: true,
            email: true,
            firstName: true,
            lastName: true,
          },
        },
      },
    });
  }

  async getSecurityMetrics() {
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const events = await db.query.securityEvents.findMany({
      where: gte(securityEvents.createdAt, oneDayAgo),
    });

    const totalEvents = events.length;
    const successfulLogins = events.filter(
      (e) => e.eventType === 'login_success',
    ).length;
    const failedLogins = events.filter(
      (e) => e.eventType === 'login_failure',
    ).length;
    const registrations = events.filter(
      (e) => e.eventType === 'registration',
    ).length;

    return {
      totalEvents,
      successfulLogins,
      failedLogins,
      registrations,
      loginSuccessRate:
        successfulLogins + failedLogins > 0
          ? (successfulLogins / (successfulLogins + failedLogins)) * 100
          : 0,
    };
  }
}
