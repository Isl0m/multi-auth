import { IsObject, IsOptional, IsString } from 'class-validator';

export class RegisterWebAuthnDto {
  @IsString()
  deviceName: string;
}

export class VerifyWebAuthnRegistrationDto {
  @IsObject()
  credential: any;

  @IsString()
  @IsOptional()
  deviceName?: string;
}

export class WebAuthnLoginDto {
  @IsString()
  email: string;
}

export class VerifyWebAuthnLoginDto {
  @IsObject()
  credential: any;
}
