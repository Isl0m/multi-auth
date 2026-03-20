import { Public } from '@/common/decorators/auth.decorator';
import { db } from '@/db';
import { Controller, Get } from '@nestjs/common';
import { sql } from 'drizzle-orm';

@Controller('health')
export class HealthController {
  @Public()
  @Get()
  async check() {
    let dbStatus = 'up';
    try {
      await db.execute(sql`SELECT 1`);
    } catch (e) {
      dbStatus = 'down';
    }

    return {
      status: 'ok',
      timestamp: new Date().toISOString(),
      services: {
        database: dbStatus,
      },
    };
  }
}
