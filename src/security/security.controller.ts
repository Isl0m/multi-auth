import { CurrentUser } from '@/common/decorators/auth.decorator';
import { Controller, Get, ParseIntPipe, Query } from '@nestjs/common';
import { SecurityService } from './security.service';

@Controller('security')
export class SecurityController {
  constructor(private readonly securityService: SecurityService) {}

  @Get('events/me')
  async getMySecurityEvents(
    @CurrentUser() user: any,
    @Query('limit', new ParseIntPipe({ optional: true })) limit?: number,
  ) {
    return this.securityService.getUserSecurityEvents(user.userId, limit || 50);
  }
}
