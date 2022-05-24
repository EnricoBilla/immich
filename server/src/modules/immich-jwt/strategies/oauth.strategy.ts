import { Inject, Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { InjectRepository } from '@nestjs/typeorm';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { Repository } from 'typeorm';
import {AuthService} from "../../../api-v1/auth/auth.service";
import { JwtPayloadDto } from '../../../api-v1/auth/dto/jwt-payload.dto';
import { UserEntity } from '../../../api-v1/user/entities/user.entity';
import { jwtSecret } from '../../../constants/jwt.constant';

@Injectable()
export class Oauth2Strategy extends PassportStrategy(Strategy, 'oauth2') {
  constructor(
    @InjectRepository(UserEntity)
    private usersRepository: Repository<UserEntity>,
    @Inject(AuthService)
    private authService: AuthService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: jwtSecret,
    });
  }

  async validate(req: Request, payload: JwtPayloadDto, headers: Headers) {
    Logger.warn('Trying OAuth2/OIDC authentication', 'AUTH STRATEGY');
    console.log(req.headers['authorization'].replace('Bearer ', ''));
    const user = await this.authService.validateUserOauth({
      accessToken: req.headers['authorization'].replace('Bearer ', ''),
    });
    Logger.debug("A");
    if (user && !user.isLocalUser) {
      Logger.debug("User ok");
      return user;
    }
  }
}
