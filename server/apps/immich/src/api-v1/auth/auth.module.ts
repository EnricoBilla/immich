import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserEntity } from '@app/database/entities/user.entity';
import { ImmichAuthModule } from '../../modules/immich-auth/immich-auth.module';
import { JwtModule } from '@nestjs/jwt';
import { jwtConfig } from '../../config/jwt.config';
import {ImmichAuthService} from "../../modules/immich-auth/immich-auth.service";

@Module({
  imports: [TypeOrmModule.forFeature([UserEntity]), JwtModule.register(jwtConfig), ImmichAuthModule],
  controllers: [AuthController],
  providers: [AuthService, ImmichAuthService],
  exports: [AuthService],
})
export class AuthModule {}
