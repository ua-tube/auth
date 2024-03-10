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
export class AuthGuard implements CanActivate {
  constructor(public readonly tokenService: TokenService) {}

  public async canActivate(ctx: ExecutionContext): Promise<boolean> | never {
    const req: Request = ctx.switchToHttp().getRequest();

    const authorizationHeader = req.headers['authorization'] || '';
    if (isEmpty(authorizationHeader)) {
      throw new UnauthorizedException();
    }

    const split = authorizationHeader.split(' ');
    if (split.length < 2) {
      throw new UnauthorizedException();
    }

    if (isEmpty(split[1])) throw new UnauthorizedException();

    req.user = await this.tokenService.verifyAccessToken(split[1]);

    return true;
  }
}
