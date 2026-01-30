import { EmailModule } from '@/email/email.module';
import { SecurityModule } from '@/security/security.module';
import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PasswordAuthController } from './password-auth.controller';
import { PasswordAuthService } from './password-auth.service';

@Module({
  imports: [JwtModule, SecurityModule, EmailModule],
  controllers: [PasswordAuthController],
  providers: [PasswordAuthService],
  exports: [PasswordAuthService],
})
export class PasswordAuthModule {}
