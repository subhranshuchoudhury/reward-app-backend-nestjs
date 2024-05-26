import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  InternalServerErrorException,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDTO, LoginDTO, RegisterDTO } from './dto';
import * as bcrypt from 'bcrypt';
import { Tokens } from './dto/types/tokens.type';
import { JwtService } from '@nestjs/jwt';
import otpGenerator from 'otp-generator';
@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
  ) {}

  // async signup(dto: AuthDTO): Promise<Tokens> {
  //   const hashedPassword = await this.hashData(dto.password);
  //   const newUser = await this.prisma.user.create({
  //     data: {
  //       email: dto.email,
  //       password: hashedPassword,
  //     },
  //   });

  //   const tokens = await this.getTokens(newUser.id, newUser.email);
  //   await this.updateRtHash(newUser.id, tokens.refresh_token);
  //   return tokens;
  // }

  // async login(dto: AuthDTO): Promise<Tokens> {
  //   const user = await this.prisma.user.findUnique({
  //     where: {
  //       email: dto.email,
  //     },
  //   });

  //   if (!user) throw new ForbiddenException('user not found');

  //   const isPassWordMatched = await bcrypt.compare(dto.password, user.password);

  //   if (!isPassWordMatched) throw new ForbiddenException('wrong credential');

  //   const tokens = await this.getTokens(user.id, user.email);
  //   await this.updateRtHash(user.id, tokens.refresh_token);

  //   return tokens;
  // }

  async register(dto: RegisterDTO) {
    try {
      const isUserExists = await this.prisma.user.findUnique({
        where: { mobile: dto.mobile },
        select: { mobile: true },
      });

      if (isUserExists) {
        return new BadRequestException('You are already registered');
      }

      const newUser = await this.prisma.user.create({
        data: {
          mobile: dto.mobile,
          name: dto.name,
          OTP: {
            create: {
              sentCount: 0,
              value: null,
            },
          },
        },
      });

      return newUser;
    } catch (error) {
      return new InternalServerErrorException();
    }
  }

  async prelogin(dto: AuthDTO) {
    try {
      const user = await this.prisma.user.findUnique({
        where: { mobile: dto.mobile },
        select: { OTP: true },
      });

      if (!user) return new ForbiddenException('user not found');

      const newOTP = otpGenerator.generate(4, {
        digits: true,
        lowerCaseAlphabets: false,
        upperCaseAlphabets: false,
        specialChars: false,
      });

      if (new Date(user.OTP?.createdAt).getDate() === new Date().getDate()) {
        // There might a bug where if user comes after one month on the same date.
        if (user.OTP.sentCount >= 10) {
          await this.prisma.oTP.update({
            where: {
              mobile: dto.mobile,
            },
            data: {
              value: null,
            },
          });

          return new ForbiddenException(
            'OTP sent limit exceeded. Try again tomorrow.',
          );
        } else {
          await this.prisma.oTP.update({
            where: {
              mobile: dto.mobile,
            },
            data: {
              value: newOTP,
              sentCount: { increment: 1 },
              createdAt: new Date(),
              attempts: 0,
            },
          });
        }
      } else {
        await this.prisma.oTP.update({
          where: {
            mobile: dto.mobile,
          },
          data: {
            value: newOTP,
            sentCount: 0,
            createdAt: new Date(),
            attempts: 0,
          },
        });
      }
    } catch (error) {
      console.log(error);
      return new InternalServerErrorException();
    }
  }

  async login(dto: LoginDTO) {
    const user = await this.prisma.user.findUnique({
      where: {
        mobile: dto.mobile,
      },
      select: { id: true, OTP: true, mobile: true },
    });

    if (!user) {
      throw new ForbiddenException();
    }

    if (dto.otp !== user.OTP.value) {
      if (user.OTP.attempts >= 3) {
        await this.prisma.oTP.update({
          where: {
            mobile: dto.mobile,
          },
          data: {
            value: null,
          },
        });
        throw new ForbiddenException('OTP attempts limit exceeded');
      } else {
        await this.prisma.oTP.update({
          where: {
            mobile: dto.mobile,
          },
          data: {
            attempts: { increment: 1 },
          },
        });
      }
      throw new ForbiddenException("OTP has been expired or doesn't match");
    }

    await this.prisma.oTP.update({
      where: {
        mobile: dto.mobile,
      },
      data: {
        value: null,
        attempts: 0,
        sentCount: 0,
      },
    });

    const tokens = await this.getTokens(user.id, user.mobile);
    await this.updateRtHash(user.id, tokens.refresh_token);

    return tokens;
  }

  async logout(userId: string) {
    await this.prisma.user.updateMany({
      where: {
        id: userId,
        AND: {
          hashedRt: {
            not: null,
          },
        },
      },
      data: {
        hashedRt: null,
      },
    });
  }

  async refreshToken(userId: string, rt: string) {
    const user = await this.prisma.user.findUnique({
      where: {
        id: userId,
      },
    });

    if (!user || !user.hashedRt) throw new ForbiddenException('no user found');

    const isRtMatch = await bcrypt.compare(rt, user.hashedRt);

    if (!isRtMatch) throw new ForbiddenException('invalid refresh token');

    const isUsedRT = await this.prisma.usedHashes.findMany({
      where: {
        userId,
        AND: {
          hash: rt,
        },
      },
    });

    if (isUsedRT.length != 0)
      throw new ForbiddenException('refresh token already used');

    const tokens = await this.getTokens(user.id, user.email);

    await this.updateRtHash(user.id, tokens.refresh_token);

    // push the used hash to the usedHashes table

    await this.prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        usedHashes: {
          create: {
            hash: rt,
          },
        },
      },
    });

    return tokens;
  }

  async updateRtHash(userId: string, rt: string) {
    const hash = await this.hashData(rt);
    await this.prisma.user.update({
      where: {
        id: userId,
      },
      data: {
        hashedRt: hash,
      },
    });
  }

  hashData(data: string) {
    return bcrypt.hash(data, 10);
  }

  async getTokens(userId: string, mobile: string): Promise<Tokens> {
    const [at, rt] = await Promise.all([
      this.jwtService.signAsync(
        {
          sub: userId,
          mobile,
        },
        {
          secret: 'at-secret',
          expiresIn: '7d',
        },
      ),
      this.jwtService.signAsync(
        {
          sub: userId,
          mobile,
        },
        {
          secret: 'rt-secret',
          expiresIn: '365 days',
        },
      ),
    ]);

    return {
      access_token: at,
      refresh_token: rt,
    };
  }
}
