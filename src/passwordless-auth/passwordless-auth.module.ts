import { EmailModule } from '@/email/email.module';
import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { SecurityModule } from '../security/security.module';
import { PasswordlessAuthController } from './passwordless-auth.controller';
import { PasswordlessAuthService } from './passwordless-auth.service';

@Module({
  imports: [JwtModule, SecurityModule, EmailModule],
  controllers: [PasswordlessAuthController],
  providers: [PasswordlessAuthService],
  exports: [PasswordlessAuthService],
})
export class PasswordlessAuthModule {}
