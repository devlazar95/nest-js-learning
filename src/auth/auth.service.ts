import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
@Injectable()
export class AuthService {
  constructor(
    private prismaService: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}
  async signin({ email, password }: AuthDto) {
    const user = await this.prismaService.user.findUnique({
      where: {
        email: email,
      },
    });
    if (!user) {
      throw new ForbiddenException('Credentials incorrect');
    }

    const passwordMatch = await argon.verify(user.hash, password);
    if (!passwordMatch) {
      throw new ForbiddenException('Credentials incorrect');
    }

    return this.signToken(user.id, user.email);
  }
  async signup(dto: AuthDto) {
    //generate pass
    const hash = await argon.hash(dto.password);
    //save user
    try {
      const user = await this.prismaService.user.create({
        data: {
          email: dto.email,
          hash,
        },
        select: {
          id: true,
          email: true,
          createdAt: true,
        },
      });
      return user;
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credentials already exist');
        }
      }
      throw error;
    }
  }

  async signToken(
    userId: number,
    email: string,
  ): Promise<{ access_token: string }> {
    const payload = {
      sub: userId,
      email,
    };
    const secret = this.config.get('JWT_SECRET');
    const access_token = await this.jwt.signAsync(payload, {
      expiresIn: '1hr',
      secret,
    });
    return {
      access_token,
    };
  }
}
