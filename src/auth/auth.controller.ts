import {
  Body,
  ConflictException,
  Controller,
  Post,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { User } from './user.schema';
import { JwtService } from '@nestjs/jwt';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { ConfigService } from '@nestjs/config';

@Controller('api/auth')
export class AuthController {
  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    private jwtService: JwtService,
  ) {}

  @MessagePattern({ cmd: 'validate_token' })
  async validateToken(@Payload() token: string) {
    console.log({token})
    const validated = this.jwtService.decode(token)
    console.log({validated})
    return validated
  }

  @Post('register')
  async register(@Body() registerDto: { username: string; password: string }) {
    const { username, password } = registerDto;
    const existingUser = await this.userModel.findOne({ username }).exec();
    if (existingUser) {
      throw new ConflictException('Username already exists');
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new this.userModel({ username, password: hashedPassword });
    await newUser.save();
    return { message: 'User registered successfully' };
  }

  @Post('login')
  async login(@Body() loginDto: { username: string; password: string }) {
    const { username, password } = loginDto;
    const user = await this.userModel.findOne({ username }).exec();
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }
    const payload = { username: user.username, sub: user._id };
    const accessToken = this.jwtService.sign(payload);
    return { accessToken };
  }

  @Post('refresh')
  async refreshToken(@Body() refreshDto: { refreshToken: string }) {
    try {
      const decoded = this.jwtService.verify(refreshDto.refreshToken);
      const payload = { username: decoded.username, sub: decoded.sub };
      const accessToken = this.jwtService.sign(payload);
      return { accessToken };
    } catch (error) {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

}
