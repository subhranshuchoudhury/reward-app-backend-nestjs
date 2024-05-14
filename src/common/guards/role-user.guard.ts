import { ExecutionContext, Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class RoleUser {
  constructor(private prisma: PrismaService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const userId = request.user['sub'];

    const user = await this.prisma.user.findUnique({
      where: {
        id: userId,
        AND: {
          role: 'USER',
        },
      },
    });

    if (user) return true;
    return false;
  }
}
