import {
  Body,
  Controller,
  Get,
  HttpCode,
  Post,
  Req,
  Res,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { Request, Response } from 'express';
import {
  CurrentSessionId,
  CurrentUser,
  IpUserAgentHeaders,
} from '../common/decorators';
import {
  CreateRecoveryTokenDto,
  LoginDto,
  ResetPasswordDto,
  SignupDto,
} from './dto';
import { AuthGuard, RefreshGuard } from './guards';
import { AuthService } from './services';
import { JwtPayload } from './types';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @HttpCode(200)
  @Post('signup')
  async signup(
    @Body() dto: SignupDto,
    @Res({ passthrough: true }) res: Response,
    @IpUserAgentHeaders() headers,
  ) {
    const { user, tokens, sessionId } = await this.authService.signup(
      dto,
      headers.userAgent,
      headers.ip,
    );

    this.authService.setCookies(sessionId, tokens.refreshToken, res);

    return { user, accessToken: tokens.accessToken };
  }

  @HttpCode(200)
  @Post('login')
  async login(
    @Body() dto: LoginDto,
    @Res({ passthrough: true }) res: Response,
    @IpUserAgentHeaders() headers,
  ) {
    const { user, tokens, sessionId } = await this.authService.login(
      dto,
      headers.userAgent,
      headers.ip,
    );

    this.authService.setCookies(sessionId, tokens.refreshToken, res);

    return { user, accessToken: tokens.accessToken };
  }

  @UseGuards(AuthGuard)
  @Get('logout')
  async logout(
    @CurrentSessionId() sessionId: string,
    @CurrentUser('id') userId: string,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    await this.authService.logout(
      userId,
      sessionId,
      req.cookies['refresh_token'] || '',
    );

    this.authService.removeCookies(res);
  }

  @UseGuards(RefreshGuard)
  @Get('refresh')
  async refresh(
    @CurrentSessionId() sessionId: string,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    try {
      const { tokens } = await this.authService.refresh(
        sessionId,
        req.cookies['refresh_token'] || '',
      );

      this.authService.setCookies(sessionId, tokens.refreshToken, res);
      return { accessToken: tokens.accessToken };
    } catch {
      this.authService.removeCookies(res);
      throw new UnauthorizedException();
    }
  }

  @HttpCode(200)
  @Post('recovery/create-token')
  createRecoveryToken(@Body() dto: CreateRecoveryTokenDto) {
    return this.authService.createRecoveryToken(dto.email);
  }

  @HttpCode(200)
  @Post('recovery/reset-password')
  async resetPassword(@Body() dto: ResetPasswordDto) {
    await this.authService.verifyRecoveryToken(dto);
    await this.authService.resetPassword(dto);
  }

  @UseGuards(AuthGuard)
  @Get('internal')
  async validateUserToken(@CurrentUser() user: JwtPayload) {
    return { id: user.id };
  }
}
