import { z } from 'zod';

export const envSchema = z.object({
  // App
  NODE_ENV: z
    .enum(['development', 'production', 'test'])
    .default('development'),
  PORT: z.coerce.number().default(3000),
  API_PREFIX: z.string().default('api/v1'),
  FRONTEND_URL: z.url().default('http://localhost:3001'),
  CORS_ORIGIN: z.string().default('http://localhost:3001'),

  // Database
  DATABASE_URL: z.string(),

  // JWT
  JWT_SECRET: z.string().default('your-secret-key'),
  JWT_EXPIRES_IN: z.string().default('24h'),
  JWT_REFRESH_SECRET: z.string().default('your-refresh-secret'),
  JWT_REFRESH_EXPIRES_IN: z.string().default('7d'),

  // Email
  EMAIL_HOST: z.string().default('smtp.gmail.com'),
  EMAIL_PORT: z.coerce.number().default(587),
  EMAIL_SECURE: z.preprocess((v) => v === 'true', z.boolean()).default(false),
  EMAIL_USER: z.string().default(''),
  EMAIL_PASSWORD: z.string().default(''),
  EMAIL_FROM: z.email().default('noreply@authsystem.com'),
  GMAIL_CLIENT_ID: z.string().default(''),
  GMAIL_CLIENT_SECRET: z.string().default(''),
  GMAIL_REFRESH_TOKEN: z.string().default(''),

  // Security
  BCRYPT_SALT_ROUNDS: z.coerce.number().default(10),
  MAGIC_LINK_SECRET: z.string().default('magic-link-secret'),
  MAGIC_LINK_EXPIRES_IN: z.string().default('15m'),
  MAX_LOGIN_ATTEMPTS: z.coerce.number().default(5),
  LOCKOUT_DURATION: z.coerce.number().default(900000),
  SESSION_SECRET: z.string().default('session-secret'),
  CSRF_COOKIE_KEY: z.string().default('_csrf'),

  // WebAuthn
  WEBAUTHN_RP_NAME: z.string().default('Auth System'),
  WEBAUTHN_RP_ID: z.string().default('localhost'),
  WEBAUTHN_ORIGIN: z.url().default('http://localhost:3001'),

  // Throttle
  THROTTLE_TTL: z.coerce.number().default(60000),
  THROTTLE_LIMIT: z.coerce.number().default(10),
});

export type Env = z.infer<typeof envSchema>;
