import { RefreshGuard } from './guard/refresh.guard';
import { JwtGuard } from './guard/jwt.guard';
/* eslint-disable prettier/prettier */
import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateAuthDto } from './dto/create-auth.dto';
import { GetUser } from './decorator/get-user.decorator';
import { User } from '@prisma/client';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  @HttpCode(HttpStatus.CREATED)
  signup(@Body() createAuthDto: CreateAuthDto) {
    return this.authService.signup(createAuthDto);
  }

  @Post('signin')
  @HttpCode(HttpStatus.OK)
  signin(@Body() createAuthDto: CreateAuthDto) {
    return this.authService.signin(createAuthDto);
  }
  @UseGuards(JwtGuard)
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  logout(@GetUser() user: User) {
    return this.authService.logout(user.id);
  }

  @UseGuards(RefreshGuard)
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  refreshTokens(@GetUser() user) {
    return this.authService.refreshTokens(
      user.sub,
      user.refreshToken,
    );
  }
}
