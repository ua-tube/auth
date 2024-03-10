import { createParamDecorator, ExecutionContext } from '@nestjs/common';

export const IpUserAgentHeaders = createParamDecorator(
  (_: undefined, context: ExecutionContext) => {
    const request = context.switchToHttp().getRequest();

    const ip = request.clientIp || '';
    const userAgent = request.headers['user-agent'] || '';

    return { ip, userAgent };
  },
);
