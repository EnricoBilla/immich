import { Inject, Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { InjectRepository } from '@nestjs/typeorm';
import { Strategy } from 'passport-custom';
import { Repository } from 'typeorm';
import {AuthService} from "../../../api-v1/auth/auth.service";
import { UserEntity } from '../../../api-v1/user/entities/user.entity';
import * as util from "util";
import {validate} from "class-validator";

@Injectable()
export class Oauth2Strategy extends PassportStrategy(Strategy, 'oauth2') {
  constructor(
    @InjectRepository(UserEntity)
    private usersRepository: Repository<UserEntity>,
    @Inject(AuthService)
    private authService: AuthService,
  ) {
    super(async (req, callback) => {
      Logger.log("inside verify", "VERIFY");
      //Logger.log(util.inspect(req));
      Logger.log(util.inspect(callback));
      return callback(null, validate(req));
    });
  }

  async validate(req: Request) {
    Logger.warn('Trying OAuth2/OIDC authentication', 'AUTH STRATEGY');
    Logger.log(util.inspect(req.headers));
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
