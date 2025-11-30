import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { RefreshTokenPayloadType } from '../types/request.types';

export const RefreshToken = createParamDecorator(
  (data: keyof RefreshTokenPayloadType | undefined, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    
    if (!request.user) return null;

    const { userId, ...payload } = request.user;
    const refreshTokenPayload: RefreshTokenPayloadType = payload;

    return data ? refreshTokenPayload?.[data] : refreshTokenPayload;
  },
);

export type RefreshTokenPayload = RefreshTokenPayloadType;
