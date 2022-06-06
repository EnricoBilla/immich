import {
  BadRequestException,
  Injectable,
  InternalServerErrorException,
  Logger,
} from '@nestjs/common';
import {InjectRepository} from '@nestjs/typeorm';
import {Repository} from 'typeorm';
import {UserEntity} from '../user/entities/user.entity';
import {LoginCredentialDto} from './dto/login-credential.dto';
import {ImmichJwtService} from '../../modules/immich-auth/immich-jwt.service';
import {JwtPayloadDto} from './dto/jwt-payload.dto';
import {SignUpDto} from './dto/sign-up.dto';
import * as bcrypt from 'bcrypt';
import {OAuthLoginDto} from "./dto/o-auth-login.dto";
import {OAuthAccessTokenDto} from "./dto/o-auth-access-token.dto";
import { ImmichOauth2Service } from '../../modules/immich-auth/immich-oauth2.service';

@Injectable()
export class AuthService {

  constructor(
    @InjectRepository(UserEntity)
    private userRepository: Repository<UserEntity>,
    private immichJwtService: ImmichJwtService,
    private immichOauth2Service: ImmichOauth2Service,
  ) {}

  private async validateLocalUser(loginCredential: LoginCredentialDto): Promise<UserEntity> {
    const user = await this.userRepository.findOne(
      { email: loginCredential.email },
      { select: ['id', 'email', 'password', 'salt'] },
    );

    if (!user) throw new BadRequestException('Incorrect email or password');

    const isAuthenticated = await this.validatePassword(user.password, loginCredential.password, user.salt);

    if (user && isAuthenticated) {
      return user;
    }

    return null;
  }

  public async loginParams() {

    const params = {
      localAuth: true,
      oauth2: false,
      discoveryUrl: null,
      clientId: null,
    };

    if (process.env.OAUTH2_ENABLE === 'true') {
      params.oauth2 = true;
      params.discoveryUrl = process.env.OAUTH2_DISCOVERY_URL;
      params.clientId = process.env.OAUTH2_CLIENT_ID;
    }

    if (process.env.LOCAL_USERS_DISABLE) {
      params.localAuth = false;
    }

    return params;

  }

  public async signUp(signUpCrendential: SignUpDto) {
    if (process.env.LOCAL_USERS_DISABLE === 'true') throw new BadRequestException("Local users not allowed!");

    const user = await this._signUp(signUpCrendential.email, true, signUpCrendential.password);

    return {
      id: user.id,
      email: user.email,
      createdAt: user.createdAt,
      isLocalUser: user.isLocalUser,
    };
  }

  async accessTokenOauth(params: OAuthAccessTokenDto) {
    if (process.env.OAUTH2_ENABLE !== 'true') throw new BadRequestException("OAuth2.0/OIDC authentication not enabled!");

    const [accessToken, refreshToken] = await this.immichOauth2Service.getAccessTokenFromAuthCode(params.code, params.redirect_uri);

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
    }
  }

  public async login(loginCredential: LoginCredentialDto) {
    if (process.env.LOCAL_USERS_DISABLE === 'true') throw new BadRequestException("Local users not allowed!");

    const validatedUser = await this.validateLocalUser(loginCredential);
    if (!validatedUser) throw new BadRequestException('Incorrect email or password');

    return await this._login(validatedUser);
  }

  public async loginOauth(params: OAuthLoginDto) {
    if (process.env.OAUTH2_ENABLE !== 'true') throw new BadRequestException("OAuth2.0/OIDC authentication not enabled!");

    const email = await this.immichOauth2Service.getEmailFromAccessToken(params.accessToken);

    let user = await this.userRepository.findOne({ email: email });

    if (!user) {
      Logger.log("User does not exist, signing up", "AUTH");
      user = await this._signUp(email, false, null);
    }

    return this._login(user);
  }

  private async _signUp(email: string, localUser: boolean, password: string | null) {
    const registerUser = await this.userRepository.findOne({ email: email });

    if (registerUser) {
      throw new BadRequestException('User exist');
    }

    const newUser = new UserEntity();
    newUser.email = email;
    if (localUser) {
      if (password === null) throw new InternalServerErrorException();
      newUser.salt = await bcrypt.genSalt();
      newUser.password = await this.hashPassword(password, newUser.salt);
      newUser.isLocalUser = true;
    } else {
      newUser.isLocalUser = false;
    }

    try {
      return await this.userRepository.save(newUser);
    } catch (e) {
      Logger.error(e, 'signUp');
      throw new InternalServerErrorException('Failed to register new user');
    }
  }

  private async _login(user: UserEntity) {
    const payload = new JwtPayloadDto(user.id, user.email);

    return {
      accessToken: await this.immichJwtService.generateToken(payload),
      userId: user.id,
      userEmail: user.email,
    };
  }

  private async hashPassword(password: string, salt: string): Promise<string> {
    return bcrypt.hash(password, salt);
  }

  private async validatePassword(hasedPassword: string, inputPassword: string, salt: string): Promise<boolean> {
    const hash = await bcrypt.hash(inputPassword, salt);
    return hash === hasedPassword;
  }

}
