import { PrismaService } from './../../prisma/prisma.service';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
/* eslint-disable prettier/prettier */
import { PassportStrategy } from '@nestjs/passport';
import {
  ExtractJwt,
  Strategy,
} from 'passport-jwt';
import { JwtPayload } from '../types';

@Injectable()
export class JwtStrategy extends PassportStrategy(
  Strategy,'jwt'
) {
  constructor(
    config: ConfigService,
    private prisma: PrismaService,
  ) {
    super({
      jwtFromRequest:
        ExtractJwt.fromAuthHeaderAsBearerToken(),

      secretOrKey: config.get('SECRET_KEY'),
    });
  }
  async validate(payload: JwtPayload) {
    const user =
      await this.prisma.user.findUnique({
        where: {
          id: payload.sub,
        },
      });
    delete user.password;
    return user;
  }
}
