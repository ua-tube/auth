import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { isEmpty } from 'class-validator';
import { Request } from 'express';
import { TokenService } from '../services';

@Injectable()
export class RefreshGuard implements CanActivate {
  constructor(public readonly tokenService: TokenService) {}

  public async canActivate(ctx: ExecutionContext): Promise<boolean> | never {
    const req: Request = ctx.switchToHttp().getRequest();

    const token = req.cookies['refresh_token'] || '';
    if (isEmpty(token)) throw new UnauthorizedException();

    await this.tokenService.verifyRefreshToken(token);

    return true;
  }
}
