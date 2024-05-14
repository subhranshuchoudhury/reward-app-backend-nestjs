import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDTO } from './dto';
import { Tokens } from './dto/types/tokens.type';
import { RoleAdmin, RoleUser, RTGuard } from 'src/common/guards';
import { ATGuard } from 'src/common/guards';
import {
  GetCurrentUser,
  GetCurrentUserID,
  PublicRoute,
} from 'src/common/decorators';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @PublicRoute()
  @Post('/signup')
  @HttpCode(HttpStatus.CREATED)
  signup(@Body() dto: AuthDTO): Promise<Tokens> {
    return this.authService.signup(dto);
  }

  @PublicRoute()
  @Post('/login')
  @HttpCode(HttpStatus.OK)
  login(@Body() dto: AuthDTO): Promise<Tokens> {
    return this.authService.login(dto);
  }

  @UseGuards(RoleUser)
  @UseGuards(ATGuard)
  @Get('/logout')
  @HttpCode(HttpStatus.OK)
  logout(@GetCurrentUserID() userId: string) {
    // return this.authService.logout(userId);
  }

  @PublicRoute()
  @UseGuards(RTGuard)
  @Get('refresh')
  @HttpCode(HttpStatus.OK)
  refreshToken(
    @GetCurrentUserID() userId: string,
    @GetCurrentUser('refreshToken') refreshToken: string,
  ) {
    return this.authService.refreshToken(userId, refreshToken);
  }
}
