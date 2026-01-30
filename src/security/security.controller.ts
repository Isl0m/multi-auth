import { CurrentUser } from '@/common/decorators/auth.decorator';
import { JwtAuthGuard } from '@/common/guards/jwt-auth.guard';
import {
  Controller,
  Get,
  ParseIntPipe,
  Query,
  UseGuards,
} from '@nestjs/common';
import { SecurityService } from './security.service';

@Controller('security')
@UseGuards(JwtAuthGuard)
export class SecurityController {
  constructor(private readonly securityService: SecurityService) {}

  /**
   * Get current user's security events
   * GET /security/events/me?limit=50
   */
  @Get('events/me')
  async getMySecurityEvents(
    @CurrentUser() user: any,
    @Query('limit', new ParseIntPipe({ optional: true })) limit?: number,
  ) {
    return this.securityService.getUserSecurityEvents(user.userId, limit || 50);
  }
}
