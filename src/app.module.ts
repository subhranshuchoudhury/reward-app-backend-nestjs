import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { UserModule } from './user/user.module';
import { PrismaModule } from './prisma/prisma.module';
import { AuthService } from './auth/auth.service';
import { AuthController } from './auth/auth.controller';
import { AuthModule } from './auth/auth.module';
import { JwtService } from '@nestjs/jwt';
import { APP_GUARD } from '@nestjs/core';
import { ATGuard } from './common/guards';

@Module({
  imports: [UserModule, PrismaModule, AuthModule],
  controllers: [AppController, AuthController],
  providers: [
    AppService,
    AuthService,
    JwtService,
    // {
    //   provide: APP_GUARD,
    //   useClass: ATGuard,
    // },
  ],
})
export class AppModule {}
