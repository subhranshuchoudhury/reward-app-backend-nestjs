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
import { AuthDTO, LoginDTO, RegisterDTO } from './dto';
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
  @Post('/register')
  @HttpCode(HttpStatus.CREATED)
  signup(@Body() dto: RegisterDTO) {
    return this.authService.register(dto);
  }

  @PublicRoute()
  @Post('/pre-login')
  @HttpCode(HttpStatus.OK)
  prelogin(@Body() dto: AuthDTO) {
    return this.authService.prelogin(dto);
  }

  @PublicRoute()
  @Post('/login')
  @HttpCode(HttpStatus.OK)
  login(@Body() dto: LoginDTO) {
    return this.authService.login(dto);
  }

  @UseGuards(RoleUser)
  @UseGuards(ATGuard)
  @Get('/logout')
  @HttpCode(HttpStatus.OK)
  logout(@GetCurrentUserID() userId: string) {
    return this.authService.logout(userId);
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
