import { EmailModule } from '@/email/email.module';
import { SecurityModule } from '@/security/security.module';
import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { WebAuthnAuthController } from './webauthn-auth.controller';
import { WebAuthnAuthService } from './webauthn-auth.service';

@Module({
  imports: [JwtModule, SecurityModule, EmailModule],
  controllers: [WebAuthnAuthController],
  providers: [WebAuthnAuthService],
  exports: [WebAuthnAuthService],
})
export class WebAuthnModule {}
