import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { JwtModule } from '@nestjs/jwt';
import { AuthController } from './auth.controller';
import { User, UserSchema } from './user.schema';
import { ConfigModule, ConfigService } from '@nestjs/config';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: User.name, schema: UserSchema }]),
    JwtModule.registerAsync({
      imports: [ConfigModule], // Import ConfigModule to access ConfigService
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_SECRET'), // Access JWT_SECRET from ConfigService
        signOptions: { expiresIn: '1h' },
      }),
      inject: [ConfigService], // Inject ConfigService
    }),
    ConfigModule,
  ],
  controllers: [AuthController],
})
export class AuthModule {}
