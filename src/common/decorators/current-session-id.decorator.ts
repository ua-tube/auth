import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { Request } from 'express';

export const CurrentSessionId = createParamDecorator(
  (_: never, context: ExecutionContext) => {
    const request: Request = context.switchToHttp().getRequest();
    return request.cookies['_app_ssid'];
  },
);
