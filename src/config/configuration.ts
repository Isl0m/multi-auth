import { z } from 'zod';

export const envSchema = z.object({
  NODE_ENV: z
    .enum(['development', 'production', 'test'])
    .default('development'),
  PORT: z.coerce.number().default(3000),
  API_PREFIX: z.string().default('api'),
  FRONTEND_URL: z.url().default('http://localhost:3001'),
  CORS_ORIGIN: z.string().default('http://localhost:3001'),

  DATABASE_URL: z.string(),

  JWT_SECRET: z.string().default('your-secret-key'),
  JWT_EXPIRES_IN: z.string().default('24h'),
  REFRESH_TOKEN_EXPIRES_MS: z.coerce.number().default(604800000),

  RESEND_API_KEY: z.string().default(''),
  EMAIL_FROM: z.email().default('onboarding@resend.dev'),

  BCRYPT_SALT_ROUNDS: z.coerce.number().default(10),
  MAGIC_LINK_EXPIRES_MS: z.coerce.number().default(900000),
  PASSWORD_RESET_EXPIRES_MS: z.coerce.number().default(3600000),
  WEBAUTHN_REGISTRATION_EXPIRES_MS: z.coerce.number().default(900000),
  MAX_LOGIN_ATTEMPTS: z.coerce.number().default(5),
  LOCKOUT_DURATION: z.coerce.number().default(900000),

  WEBAUTHN_RP_NAME: z.string().default('Auth System'),
  WEBAUTHN_RP_ID: z.string().default('localhost'),
  WEBAUTHN_ORIGIN: z.url().default('http://localhost:3001'),

  THROTTLE_TTL: z.coerce.number().default(60000),
  THROTTLE_LIMIT: z.coerce.number().default(10),
});

export type Env = z.infer<typeof envSchema>;
