import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { JwtPayload } from '../../auth/types';

export const CurrentUser = createParamDecorator(
  (data: keyof JwtPayload, context: ExecutionContext) => {
    const user = context.switchToHttp().getRequest()?.user;

    if (!user) return undefined;

    return data ? user[data] : user;
  },
);
