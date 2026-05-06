import { AuthModule } from '@/auth/auth.module';
import { ThrottlerExceptionFilter } from '@/common/filters/throttler-exception.filter';
import { JwtAuthGuard } from '@/common/guards/jwt-auth.guard';
import { JwtStrategy } from '@/common/strategies/jwt.strategy';
import { Env, envSchema } from '@/config/configuration';
import { EmailModule } from '@/email/email.module';
import { PasswordAuthModule } from '@/password-auth/password-auth.module';
import { PasswordlessAuthModule } from '@/passwordless-auth/passwordless-auth.module';
import { SecurityModule } from '@/security/security.module';
import { WebAuthnModule } from '@/webauthn-auth/webauthn-auth.module';
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { APP_FILTER, APP_GUARD } from '@nestjs/core';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import z from 'zod';
import { HealthController } from './common/controllers/health.controller';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      validate: (config) => {
        const parsed = envSchema.safeParse(config);
        if (!parsed.success) {
          console.error(
            '❌ Invalid environment variables:',
            z.treeifyError(parsed.error),
          );
          throw new Error('Config validation failed');
        }
        return parsed.data;
      },
    }),
    ThrottlerModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: async (configService: ConfigService<Env, true>) => ({
        throttlers: [
          {
            ttl: configService.get('THROTTLE_TTL', { infer: true }),
            limit: configService.get('THROTTLE_LIMIT', { infer: true }),
          },
        ],
      }),
    }),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: async (configService: ConfigService<Env, true>) => ({
        secret: configService.get('JWT_SECRET', { infer: true }),
        signOptions: {
          expiresIn: configService.get('JWT_EXPIRES_IN', { infer: true }),
        },
      }),
    }),
    PassportModule,
    AuthModule,
    PasswordAuthModule,
    PasswordlessAuthModule,
    WebAuthnModule,
    SecurityModule,
    EmailModule,
  ],
  controllers: [HealthController],
  providers: [
    JwtStrategy,
    {
      provide: APP_GUARD,
      useClass: JwtAuthGuard,
    },
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
    {
      provide: APP_FILTER,
      useClass: ThrottlerExceptionFilter,
    },
  ],
})
export class AppModule {}
