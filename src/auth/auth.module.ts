import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PrismaModule } from '../prisma';
import { AuthController, HealthController } from './controllers';
import { AuthService, TokenService } from './services';
import { JwtAtStrategy, JwtRtStrategy } from './strategies';
import { ConfigService } from '@nestjs/config';

@Module({
  imports: [
    JwtModule.registerAsync({
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_AT_SECRET'),
        signOptions: {
          subject: 'auth',
          expiresIn: '60m',
          issuer: configService.get<string>('JWT_ISSUER'),
          audience: configService.get<string>('JWT_AUDIENCE'),
        },
        verifyOptions: {
          subject: 'auth',
          ignoreExpiration: false,
          issuer: configService.get<string>('JWT_ISSUER'),
          audience: configService.get<string>('JWT_AUDIENCE'),
        },
      }),
    }),
    PrismaModule,
  ],
  controllers: [AuthController, HealthController],
  providers: [AuthService, TokenService, JwtAtStrategy, JwtRtStrategy],
})
export class AuthModule {}
