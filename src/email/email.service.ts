import { Env } from '@/config/configuration';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';

@Injectable()
export class EmailService {
  private transporter: nodemailer.Transporter;

  constructor(private readonly configService: ConfigService<Env, true>) {
    this.transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        type: 'OAuth2',
        user: this.configService.get('EMAIL_USER', { infer: true }),
        clientId: this.configService.get('GMAIL_CLIENT_ID', { infer: true }),
        clientSecret: this.configService.get('GMAIL_CLIENT_SECRET', {
          infer: true,
        }),
        refreshToken: this.configService.get('GMAIL_REFRESH_TOKEN', {
          infer: true,
        }),
      },
    });
  }

  async sendMagicLink(email: string, magicLink: string) {
    await this.transporter.sendMail({
      from: this.configService.get('EMAIL_FROM', { infer: true }),
      to: email,
      subject: 'Your Magic Link - Auth System',
      html: `
        <h2>Login to Your Account</h2>
        <p>Click the link below to log in. This link will expire in 15 minutes.</p>
        <a href="${magicLink}" style="display: inline-block; padding: 10px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px;">
          Log In
        </a>
        <p>If you didn't request this, please ignore this email.</p>
      `,
    });
  }

  async sendPasswordResetEmail(email: string, resetUrl: string) {
    await this.transporter.sendMail({
      from: this.configService.get('EMAIL_FROM', { infer: true }),
      to: email,
      subject: 'Password Reset Request - Auth System',
      html: `
        <h2>Reset Your Password</h2>
        <p>Click the link below to reset your password. This link will expire in 1 hour.</p>
        <a href="${resetUrl}" style="display: inline-block; padding: 10px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px;">
          Reset Password
        </a>
        <p>If you didn't request this, please ignore this email.</p>
      `,
    });
  }

  async sendWelcomeEmail(email: string, name?: string) {
    await this.transporter.sendMail({
      from: this.configService.get('EMAIL_FROM', { infer: true }),
      to: email,
      subject: 'Welcome to Auth System',
      html: `
        <h2>Welcome${name ? ` ${name}` : ''}!</h2>
        <p>Thank you for registering with Auth System.</p>
        <p>You can now log in using your credentials or passwordless authentication.</p>
      `,
    });
  }
}
