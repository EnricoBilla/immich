import {BadRequestException, forwardRef, Inject, Injectable, Logger, UnauthorizedException} from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { InjectRepository } from '@nestjs/typeorm';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { Repository } from 'typeorm';
import { JwtPayloadDto } from '../../../api-v1/auth/dto/jwt-payload.dto';
import { UserEntity } from '../../../api-v1/user/entities/user.entity';
import { jwtSecret } from '../../../constants/jwt.constant';
import * as util from "util";
import {AuthService} from "../../../api-v1/auth/auth.service";
import {OAuthLoginDto} from "../../../api-v1/auth/dto/o-auth-login.dto";
import {lastValueFrom} from "rxjs";
import {AxiosResponse} from "axios";
import {OAuthAccessTokenDto} from "../../../api-v1/auth/dto/o-auth-access-token.dto";

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
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
      passReqToCallback: true,
    });
  }

  async validate(req: Request, payload: JwtPayloadDto, headers: Headers) {

    if (process.env.LOCAL_USERS_DISABLE !== 'true') {
      Logger.debug('Trying JWT authentication', 'AUTH STRATEGY');
      const { userId } = payload;
      const user = await this.usersRepository.findOne({ id: userId });
      if (user && user.isLocalUser) return user;
    }

    if (process.env.OAUTH2_ENABLE === 'true') {
      Logger.debug('Trying OAuth2/OIDC authentication', 'AUTH STRATEGY');
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

    throw new UnauthorizedException();

  }
}
