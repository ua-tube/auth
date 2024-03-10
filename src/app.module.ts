import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { APP_INTERCEPTOR } from '@nestjs/core';
import Joi from 'joi';
import { AuthModule } from './auth/auth.module';
import { LoggingInterceptor } from './common/interceptors';

@Module({
  imports: [
    ConfigModule.forRoot({
      cache: true,
      isGlobal: true,
      validationSchema: Joi.object({
        NODE_ENV: Joi.valid('development', 'production', 'test').required(),
        CLIENT_URL: Joi.string().required(),
        HTTP_HOST: Joi.string().required(),
        HTTP_PORT: Joi.number().required(),
        JWT_AT_SECRET: Joi.string().required(),
        JWT_RT_SECRET: Joi.string().required(),
        JWT_ISSUER: Joi.string().required(),
        JWT_AUDIENCE: Joi.string().required(),
        DATABASE_URL: Joi.string().required(),
      }),
    }),
    AuthModule,
  ],
  providers: [
    {
      provide: APP_INTERCEPTOR,
      useClass: LoggingInterceptor,
    },
  ],
})
export class AppModule {}
