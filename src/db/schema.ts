import { relations } from 'drizzle-orm';
import {
  boolean,
  index,
  integer,
  jsonb,
  pgEnum,
  pgTable,
  text,
  timestamp,
  uuid,
  varchar,
} from 'drizzle-orm/pg-core';

// Enums
export const authMethodEnum = pgEnum('auth_method', [
  'password',
  'passwordless',
  'webauthn',
]);

export const eventTypeEnum = pgEnum('event_type', [
  'login_success',
  'login_failure',
  'registration',
  'password_reset',
  'logout',
  'mfa_enabled',
  'mfa_disabled',
  'account_locked',
  'account_unlocked',
  'webauthn_registered',
  'webauthn_authenticated',
  'magic_link_sent',
  'magic_link_used',
]);

// Users table
export const users = pgTable(
  'users',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    email: varchar('email', { length: 255 }).notNull().unique(),
    emailVerified: boolean('email_verified').default(false),
    firstName: varchar('first_name', { length: 100 }),
    lastName: varchar('last_name', { length: 100 }),
    isActive: boolean('is_active').default(true),
    isLocked: boolean('is_locked').default(false),
    lockoutUntil: timestamp('lockout_until'),
    failedLoginAttempts: integer('failed_login_attempts').default(0),
    lastLoginAt: timestamp('last_login_at'),
    lastLoginIp: varchar('last_login_ip', { length: 45 }),
    createdAt: timestamp('created_at').defaultNow(),
    updatedAt: timestamp('updated_at')
      .defaultNow()
      .$onUpdate(() => new Date()),
  },
  (table) => [index('email_idx').on(table.email)],
);

// Password Authentication table
export const passwordAuth = pgTable(
  'password_auth',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    passwordHash: varchar('password_hash', { length: 255 }).notNull(),
    mfaEnabled: boolean('mfa_enabled').default(false),
    mfaSecret: varchar('mfa_secret', { length: 255 }),
    passwordChangedAt: timestamp('password_changed_at'),
    createdAt: timestamp('created_at').defaultNow(),
    updatedAt: timestamp('updated_at')
      .defaultNow()
      .$onUpdate(() => new Date()),
  },
  (table) => [index('password_auth_user_id_idx').on(table.userId)],
);

// WebAuthn Credentials table
export const webauthnCredentials = pgTable(
  'webauthn_credentials',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    credentialId: text('credential_id').notNull().unique(),
    credentialPublicKey: text('credential_public_key').notNull(),
    counter: integer('counter').notNull().default(0),
    credentialDeviceType: varchar('credential_device_type', { length: 32 }),
    credentialBackedUp: boolean('credential_backed_up').default(false),
    transports: jsonb('transports'),
    deviceName: varchar('device_name', { length: 255 }),
    lastUsedAt: timestamp('last_used_at'),
    createdAt: timestamp('created_at').defaultNow(),
  },
  (table) => [
    index('webauthn_user_id_idx').on(table.userId),
    index('credential_id_idx').on(table.credentialId),
  ],
);

// Magic Link Tokens table
export const magicLinkTokens = pgTable(
  'magic_link_tokens',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    userId: uuid('user_id').references(() => users.id, {
      onDelete: 'cascade',
    }),
    email: varchar('email', { length: 255 }), // Used for Just-in-Time user creation
    token: varchar('token', { length: 255 }).notNull().unique(),
    expiresAt: timestamp('expires_at').notNull(),
    usedAt: timestamp('used_at'),
    ipAddress: varchar('ip_address', { length: 45 }),
    userAgent: text('user_agent'),
    createdAt: timestamp('created_at').defaultNow(),
  },
  (table) => [
    index('token_idx').on(table.token),
    index('magic_link_user_id_idx').on(table.userId),
    index('magic_link_email_idx').on(table.email),
  ],
);

// Refresh Tokens table
export const refreshTokens = pgTable(
  'refresh_tokens',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    token: varchar('token', { length: 500 }).notNull().unique(),
    expiresAt: timestamp('expires_at').notNull(),
    isRevoked: boolean('is_revoked').default(false),
    ipAddress: varchar('ip_address', { length: 45 }),
    userAgent: text('user_agent'),
    createdAt: timestamp('created_at').defaultNow(),
  },
  (table) => [
    index('refresh_token_idx').on(table.token),
    index('refresh_token_user_id_idx').on(table.userId),
  ],
);

// Security Events table
export const securityEvents = pgTable(
  'security_events',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    userId: uuid('user_id').references(() => users.id, {
      onDelete: 'set null',
    }),
    eventType: eventTypeEnum('event_type').notNull(),
    authMethod: authMethodEnum('auth_method'),
    ipAddress: varchar('ip_address', { length: 45 }),
    userAgent: text('user_agent'),
    success: boolean('success').notNull(),
    errorMessage: text('error_message'),
    metadata: jsonb('metadata'),
    createdAt: timestamp('created_at').defaultNow(),
  },
  (table) => [
    index('security_events_user_id_idx').on(table.userId),
    index('event_type_idx').on(table.eventType),
    index('created_at_idx').on(table.createdAt),
  ],
);

// Password Reset Tokens table
export const passwordResetTokens = pgTable(
  'password_reset_tokens',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    token: varchar('token', { length: 255 }).notNull().unique(),
    expiresAt: timestamp('expires_at').notNull(),
    usedAt: timestamp('used_at'),
    createdAt: timestamp('created_at').defaultNow(),
  },
  (table) => [
    index('reset_token_idx').on(table.token),
    index('reset_token_user_id_idx').on(table.userId),
  ],
);

// WebAuthn Registration Tokens table
export const webauthnRegistrationTokens = pgTable(
  'webauthn_registration_tokens',
  {
    id: uuid('id').primaryKey().defaultRandom(),
    email: varchar('email', { length: 255 }).notNull(),
    token: varchar('token', { length: 255 }).notNull().unique(),
    expiresAt: timestamp('expires_at').notNull(),
    usedAt: timestamp('used_at'),
    ipAddress: varchar('ip_address', { length: 45 }),
    userAgent: text('user_agent'),
    createdAt: timestamp('created_at').defaultNow(),
  },
  (table) => [
    index('webauthn_reg_token_idx').on(table.token),
    index('webauthn_reg_email_idx').on(table.email),
  ],
);

// Relations
export const usersRelations = relations(users, ({ many, one }) => ({
  passwordAuth: one(passwordAuth),
  webauthnCredentials: many(webauthnCredentials),
  magicLinkTokens: many(magicLinkTokens),
  refreshTokens: many(refreshTokens),
  securityEvents: many(securityEvents),
  passwordResetTokens: many(passwordResetTokens),
}));

export const passwordAuthRelations = relations(passwordAuth, ({ one }) => ({
  user: one(users, {
    fields: [passwordAuth.userId],
    references: [users.id],
  }),
}));

export const webauthnCredentialsRelations = relations(
  webauthnCredentials,
  ({ one }) => ({
    user: one(users, {
      fields: [webauthnCredentials.userId],
      references: [users.id],
    }),
  }),
);

export const magicLinkTokensRelations = relations(
  magicLinkTokens,
  ({ one }) => ({
    user: one(users, {
      fields: [magicLinkTokens.userId],
      references: [users.id],
    }),
  }),
);

export const refreshTokensRelations = relations(refreshTokens, ({ one }) => ({
  user: one(users, {
    fields: [refreshTokens.userId],
    references: [users.id],
  }),
}));

export const securityEventsRelations = relations(securityEvents, ({ one }) => ({
  user: one(users, {
    fields: [securityEvents.userId],
    references: [users.id],
  }),
}));

export const passwordResetTokensRelations = relations(
  passwordResetTokens,
  ({ one }) => ({
    user: one(users, {
      fields: [passwordResetTokens.userId],
      references: [users.id],
    }),
  }),
);

export const webauthnRegistrationTokensRelations = relations(
  webauthnRegistrationTokens,
  () => ({}),
);

// Types
export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;

export type PasswordAuth = typeof passwordAuth.$inferSelect;
export type NewPasswordAuth = typeof passwordAuth.$inferInsert;

export type WebauthnCredential = typeof webauthnCredentials.$inferSelect;
export type NewWebauthnCredential = typeof webauthnCredentials.$inferInsert;

export type MagicLinkToken = typeof magicLinkTokens.$inferSelect;
export type NewMagicLinkToken = typeof magicLinkTokens.$inferInsert;

export type RefreshToken = typeof refreshTokens.$inferSelect;
export type NewRefreshToken = typeof refreshTokens.$inferInsert;

export type SecurityEvent = typeof securityEvents.$inferSelect;
export type NewSecurityEvent = typeof securityEvents.$inferInsert;

export type PasswordResetToken = typeof passwordResetTokens.$inferSelect;
export type NewPasswordResetToken = typeof passwordResetTokens.$inferInsert;

export type WebauthnRegistrationToken =
  typeof webauthnRegistrationTokens.$inferSelect;
export type NewWebauthnRegistrationToken =
  typeof webauthnRegistrationTokens.$inferInsert;
