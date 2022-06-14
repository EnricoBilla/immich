import {Body, Controller, Get, Logger, Post, UseGuards, ValidationPipe} from '@nestjs/common';
import { AuthUserDto, GetAuthUser } from '../../decorators/auth-user.decorator';
import { AuthService } from './auth.service';
import { LoginCredentialDto } from './dto/login-credential.dto';
import { SignUpDto } from './dto/sign-up.dto';
import {ImmichAuthGuard} from "../../modules/immich-auth/guards/immich-auth.guard";

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('/login')
  async login(@Body(ValidationPipe) loginCredential: LoginCredentialDto) {
    return await this.authService.login(loginCredential);
  }

  @Post('/admin-sign-up')
  async adminSignUp(@Body(ValidationPipe) signUpCrendential: SignUpDto) {
    return await this.authService.adminSignUp(signUpCrendential);
  }

  @UseGuards(ImmichAuthGuard)
  @Post('/validateToken')
  async validateToken(@GetAuthUser() authUser: AuthUserDto) {
    return await this.authService.validateToken(authUser);
  }

  @Get('/loginParams')
  async loginParams() {
    return await this.authService.loginParams();
  }

}
