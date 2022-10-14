import { PrismaService } from './../../prisma/prisma.service';

import {
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
/* eslint-disable prettier/prettier */
import { PassportStrategy } from '@nestjs/passport';
import {
  ExtractJwt,
  Strategy,
} from 'passport-jwt';
import { Request } from 'express';
import { JwtPayload } from '../types';

@Injectable()
export class JwtRefreshStrategy extends PassportStrategy(
  Strategy,'jwt-refresh'
) {
  constructor(
    config: ConfigService,
    private prisma: PrismaService,
  ) {
    super({
      jwtFromRequest:
        ExtractJwt.fromAuthHeaderAsBearerToken(),
      passReqToCallback: true,

      secretOrKey: config.get('REFRESH_KEY'),
    });
  }
  async validate(
    payload:  JwtPayload,
    req: Request,
  ) {
    const refreshToken = req
      ?.get('authorization')
      ?.replace('Bearer', '')
      .trim();

    if (!refreshToken)
      throw new ForbiddenException(
        'Refresh token malformed',
      );

    return {
      ...payload,
      refreshToken,
    };
  }
}
