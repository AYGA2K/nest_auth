import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from './../prisma/prisma.service';
import {
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { CreateAuthDto } from './dto/create-auth.dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { JwtPayload, Tokens } from './types';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}
  async signup(createAuthDto: CreateAuthDto) {
    const hash = await argon.hash(createAuthDto.password);
    try {
      const user = await this.prisma.user.create({
        data: {
          email: createAuthDto.email,
          password: hash,
        },
      });
      const tokens = this.getTokens(user.id, user.email);
      await this.updateRthash(
        user.id,
        (
          await tokens
        ).refresh_token,
      );
      return tokens;
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Crendatials taken');
        }
      }
    }
  }

  async signin(createAuthDto: CreateAuthDto) {
    const user = await this.prisma.user.findUnique({
      where: {
        email: createAuthDto.email,
      },
    });
    if (!user) {
      throw new ForbiddenException('Crendatials incorrect');
    }
    const passmatches = await argon.verify(
      user.password,
      createAuthDto.password,
    );
    if (!passmatches) {
      throw new ForbiddenException('Crendatials incorrect');
    }

    const tokens = this.getTokens(user.id, user.email);
    await this.updateRthash(
      user.id,
          (await tokens)
      .refresh_token,
    );
    return tokens;
  }

  async getTokens(
    userId: number,
    email: string,
  ): Promise<Tokens> {
    const jwtPayload: JwtPayload = {
      sub: userId,
      email: email,
    };

    const [at, rt] = await Promise.all([
      this.jwt.signAsync(jwtPayload, {
        secret: this.config.get<string>('SECRET_KEY'),
        expiresIn: '15m',
      }),
      this.jwt.signAsync(jwtPayload, {
        secret: this.config.get<string>('REFRESH_KEY'),
        expiresIn: '7d',
      }),
    ]);

    return {
      access_token: at,
      refresh_token: rt,
    };
  }
  async updateRthash(userId: number, rt: string) {
    const hash = await argon.hash(rt);
    await this.prisma.user.update({
      where: { id: userId },
      data: { hashedRt: hash },
    });
  }
}
