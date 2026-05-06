import { SecurityService } from '@/security/security.service';
import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  Injectable,
} from '@nestjs/common';
import { ThrottlerException } from '@nestjs/throttler';
import type { Request, Response } from 'express';

@Catch(ThrottlerException)
@Injectable()
export class ThrottlerExceptionFilter implements ExceptionFilter {
  constructor(private readonly securityService: SecurityService) {}

  async catch(exception: ThrottlerException, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const request = ctx.getRequest<Request>();
    const response = ctx.getResponse<Response>();

    await this.securityService.logSecurityEvent({
      userId: (request as any).user?.userId ?? null,
      eventType: 'login_failure',
      authMethod: null,
      ipAddress: request.ip ?? null,
      userAgent: request.headers['user-agent'] ?? null,
      success: false,
      errorMessage: 'Rate limit exceeded',
    });

    response.status(429).json({
      statusCode: 429,
      message: 'Too Many Requests',
      error: 'Rate limit exceeded',
    });
  }
}
