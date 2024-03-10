import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { compare, genSalt, hash } from 'bcryptjs';
import { CookieOptions, Response } from 'express';
import moment from 'moment';
import { v4, v5 } from 'uuid';
import { PrismaService } from '../../prisma';
import { LoginDto, ResetPasswordDto, SignupDto, UserInfoDto } from '../dto';
import { TokenService } from './token.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly tokenService: TokenService,
    private readonly prisma: PrismaService,
  ) {}

  async signup({ email, password }: SignupDto, userAgent: string, ip: string) {
    const candidate = await this.prisma.user.findUnique({ where: { email } });
    if (candidate) {
      throw new BadRequestException(`User with provided email already exists`);
    }

    const salt = await genSalt(10);
    const hashPassword = await hash(password, salt);
    const user = await this.prisma.user.create({
      data: { email, password: hashPassword },
    });
    const userInfo = new UserInfoDto(user);

    const session = await this.createSession(userInfo, userAgent, ip);

    return { user: userInfo, ...session };
  }

  async login({ email, password }: LoginDto, userAgent: string, ip: string) {
    const candidate = await this.prisma.user.findUnique({ where: { email } });
    if (!candidate) throw new BadRequestException('Invalid email or password');

    const isPasswordValid = await compare(password, candidate.password);
    if (!isPasswordValid)
      throw new BadRequestException('Invalid email or password');

    const userInfo = new UserInfoDto(candidate);
    const session = await this.createSession(userInfo, userAgent, ip);

    return { user: userInfo, ...session };
  }

  async logout(userId: string, sessionId: string, refreshToken: string) {
    const session = await this.prisma.userSession.findUnique({
      where: { id: sessionId, userId },
    });

    if (session?.userId === userId && session?.refreshToken === refreshToken) {
      await this.prisma.userSession.deleteMany({ where: { id: session.id } });
    }
  }

  async refresh(sessionId: string, refreshToken: string) {
    const session = await this.prisma.userSession.findUnique({
      where: { id: sessionId },
      select: {
        id: true,
        refreshToken: true,
        User: { select: { id: true, email: true } },
      },
    });

    if (!session) throw new UnauthorizedException();
    if (session.refreshToken !== refreshToken)
      throw new UnauthorizedException();

    const tokens = await this.tokenService.generateTokens(
      { id: session.User.id, email: session.User.email },
      session.id,
    );

    await this.prisma.userSession.update({
      where: { id: session.id },
      data: { refreshToken: tokens.refreshToken },
    });

    return { tokens };
  }

  async createRecoveryToken(email: string) {
    const user = await this.prisma.user.findUnique({ where: { email } });

    if (!user) throw new BadRequestException('User not found');

    const token = this.generateUuid(JSON.stringify({ email }));

    const salt = await genSalt(10);
    const tokenHash = await hash(token, salt);

    const body = {
      tokenHash,
      expiresAt: moment.utc().add(30, 'minutes').toDate(),
    };

    await this.prisma.recoveryToken.upsert({
      where: { userId: user.id },
      create: {
        userId: user.id,
        ...body,
      },
      update: body,
    });

    // TODO: send email
    // this.eventEmitter.emit('mail.send.recovery', { email, token });
  }

  async verifyRecoveryToken({ email, token }: ResetPasswordDto) {
    const user = await this.prisma.user.findUnique({ where: { email } });

    if (!user) throw new BadRequestException();

    const recoveryToken = await this.prisma.recoveryToken.findFirst({
      where: { userId: user.id },
    });

    if (!recoveryToken) throw new BadRequestException('Invalid recovery token');

    if (moment(recoveryToken.expiresAt).diff(moment.utc(), 'minutes') > 30) {
      await this.prisma.recoveryToken.delete({ where: { userId: user.id } });
      throw new BadRequestException('Token expired');
    }

    const valid = await compare(token, recoveryToken.tokenHash);

    if (!valid) throw new BadRequestException('Invalid token');
  }

  async resetPassword({ email, newPassword }: ResetPasswordDto) {
    const salt = await genSalt(10);
    const passwordHash = await hash(newPassword, salt);

    const user = await this.prisma.user.update({
      where: { email },
      data: { password: passwordHash },
      select: {
        id: true,
      },
    });

    if (!user) throw new BadRequestException();

    await this.prisma.$transaction([
      this.prisma.recoveryToken.deleteMany({
        where: { userId: user.id },
      }),
      this.prisma.userSession.deleteMany({
        where: { userId: user.id },
      }),
    ]);
  }

  setCookies(sessionId: string, refreshToken: string, res: Response) {
    const cookieConfig: CookieOptions = {
      maxAge: 30 * 24 * 60 * 60 * 1000,
      httpOnly: true,
    };

    res.cookie('_app_ssid', sessionId, cookieConfig);
    res.cookie('refresh_token', refreshToken, cookieConfig);
  }

  removeCookies(res: Response) {
    res.cookie('_app_ssid', '', { maxAge: 0, httpOnly: true });
    res.cookie('refresh_token', '', { maxAge: 0, httpOnly: true });
  }

  private generateUuid(data: string) {
    return v5(data, v4()).replace(/-/g, '');
  }

  private async createSession(
    userInfo: UserInfoDto,
    userAgent: string,
    ip: string,
  ) {
    const session = await this.prisma.userSession.upsert({
      where: {
        userAgent_userId: {
          userAgent,
          userId: userInfo.id,
        },
      },
      create: {
        userId: userInfo.id,
        refreshToken: '',
        userAgent,
        ip,
      },
      update: { ip },
    });
    try {
      const tokens = await this.tokenService.generateTokens(
        { id: userInfo.id, email: userInfo.email },
        session.id,
      );
      await this.prisma.userSession.update({
        where: { id: session.id },
        data: { refreshToken: tokens.refreshToken },
      });
      return { tokens, sessionId: session.id };
    } catch {
      await this.prisma.userSession.deleteMany({ where: { id: session.id } });
      throw new InternalServerErrorException('Unexpected error');
    }
  }
}
