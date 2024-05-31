import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from '../types';

@Injectable()
export class TokenService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  async generateTokens(payload: JwtPayload, sessionId: string) {
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload),
      this.jwtService.signAsync(
        { id: payload.id, sessionId },
        {
          subject: 'refresh_auth',
          secret: this.configService.get<string>('JWT_RT_SECRET'),
          expiresIn: '30d',
        },
      ),
    ]);

    return { accessToken, refreshToken };
  }

  async verifyAccessToken(token: string) {
    try {
      return this.jwtService.verifyAsync(token);
    } catch {
      throw new UnauthorizedException({ code: 3 });
    }
  }

  async verifyRefreshToken(token: string) {
    try {
      return this.jwtService.verifyAsync(token, {
        subject: 'refresh_auth',
        secret: this.configService.get<string>('JWT_RT_SECRET'),
      });
    } catch {
      throw new UnauthorizedException({ code: 4 });
    }
  }
}
