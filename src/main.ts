import { Env } from '@/config/configuration';
import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NestFactory } from '@nestjs/core';
import { NestExpressApplication } from '@nestjs/platform-express';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);
  app.set('trust proxy', true);

  const configService = app.get(ConfigService<Env, true>);

  app.use(helmet());

  app.use(cookieParser());

  app.enableCors({
    origin: configService.get('CORS_ORIGIN', { infer: true }),
    credentials: true,
  });

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  const apiPrefix = configService.get('API_PREFIX', { infer: true });
  app.setGlobalPrefix(apiPrefix);

  const port = configService.get('PORT', { infer: true });
  await app.listen(port);

  console.log(`🚀 Application is running on: http://localhost:${port}`);
  console.log(`📚 API available at: http://localhost:${port}/${apiPrefix}`);
}

bootstrap();
