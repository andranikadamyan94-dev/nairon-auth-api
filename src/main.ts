import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { AppModule } from './app.module';
import * as cookieParser from 'cookie-parser';
import { PrismaExceptionFilter } from './shared/filters/prisma-exception.filter';
import { armenianValidationPipe } from './shared/validation-messages';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  // Behind the gateway every request used to arrive with the gateway's IP, so
  // the per-IP throttle became ONE company-wide bucket (prod /me and even
  // login 429s). The gateway now sends X-Forwarded-For; trust exactly one hop.
  app.getHttpAdapter().getInstance().set('trust proxy', 1);
  app.use(cookieParser());

  app.enableCors({
    origin: [
      'http://localhost:3000',
      'http://localhost:3004',
      'http://localhost:4001',
      'http://localhost:4002',
      'http://localhost:4003',
      'http://localhost:4004',
      'https://gateway.nairon.am',
      'https://nairon.am',
      'https://www.nairon.am',
      'https://crm.nairon.am',
      'https://finance.nairon.am',
      'https://warehouse.nairon.am',
      'https://staging.nairon.am',
      'https://staging-crm.nairon.am',
      'https://staging-finance.nairon.am',
      'https://staging-warehouse.nairon.am',
      ...(process.env.FRONTEND_URL?.split(',').map((u) => u.trim()).filter(Boolean) ?? []),
    ].filter(Boolean),
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    // Every authenticated request from any of the client apps carries
    // X-Entity-ID (set globally by each app's axios interceptor whenever an
    // entity is selected) — crm-api already allows it; this app didn't, so
    // any authenticated call here (logout, etc.) with an entity selected
    // failed the CORS preflight before it ever reached a route.
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Entity-ID'],
  });

  app.setGlobalPrefix('api');

  app.useGlobalPipes(armenianValidationPipe({ transformOptions: { enableImplicitConversion: true } }));

  // Without this a broken unique constraint (e.g. a duplicate user email)
  // escapes as a bare 500 with no body, leaving the UI nothing to show.
  app.useGlobalFilters(new PrismaExceptionFilter());

  const config = new DocumentBuilder()
    .setTitle('Nairon Auth API')
    .setDescription('Authentication service')
    .setVersion('1.0')
    .addBearerAuth()
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('docs', app, document);

  await app.listen(Number(process.env.PORT) || 3001, '0.0.0.0');
}
bootstrap();