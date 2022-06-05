import {BadRequestException, Injectable, Logger, UnauthorizedException} from '@nestjs/common';
import {HttpService} from "@nestjs/axios";
import {OAuthLoginDto} from "../../api-v1/auth/dto/o-auth-login.dto";
import {lastValueFrom} from "rxjs";
import {AxiosResponse} from "axios";
import {InjectRepository} from "@nestjs/typeorm";
import {UserEntity} from "../../api-v1/user/entities/user.entity";
import {Repository} from "typeorm";
import {OAuthAccessTokenDto} from "../../api-v1/auth/dto/o-auth-access-token.dto";
import util from "util";

@Injectable()
export class ImmichOauth2Service {

  private oauthUserinfoEndpoint: string;
  private oauthTokenEndpoint: string;

  constructor(
      @InjectRepository(UserEntity)
      private userRepository: Repository<UserEntity>,
      private httpService: HttpService,
  ) {}

  public async validateUserOauth(params: OAuthLoginDto) {
    if (process.env.OAUTH2_ENABLE !== 'true') throw new BadRequestException("OAuth2.0/OIDC authentication not enabled!");

    const userinfoEndpoint = await this.getUserinfoEndpoint();

    const headersRequest = {
      'Authorization': `Bearer ${params.accessToken}`,
    };

    const response = await lastValueFrom(await this.httpService
        .get(userinfoEndpoint, { headers: headersRequest }))
        .catch((e) => Logger.log(e, "AUTH")) as AxiosResponse;

    if (!response || response.status !== 200) {
      throw new UnauthorizedException('Cannot validate token');
    }

    Logger.debug("Called userinfo endpoint", "AUTH");

    const email = response.data['email'];
    if (!email || email === "") throw new BadRequestException("User email not found", "AUTH");

    Logger.debug(email);

    const user = await this.userRepository.findOne({ email: email });

    return user;
  }

  async accessTokenOauth(params: OAuthAccessTokenDto) {
    if (process.env.OAUTH2_ENABLE !== 'true') throw new BadRequestException("OAuth2.0/OIDC authentication not enabled!");

    const tokenEndpoint = await this.getTokenEndpoint();

    const headersRequest = {
      'Content-Type': 'application/x-www-form-urlencoded',
    };

    const reqParams = new URLSearchParams();
    reqParams.append('grant_type', 'authorization_code');
    reqParams.append('code', params.code);
    reqParams.append('client_id', process.env.OAUTH2_CLIENT_ID);
    reqParams.append('client_secret', process.env.OAUTH2_CLIENT_SECRET);
    reqParams.append('redirect_uri', params.redirect_uri);

    const response = await lastValueFrom(await this.httpService
        .post(tokenEndpoint, reqParams, { headers: headersRequest }))
        .catch((e) => {
          Logger.log(util.inspect(e), "AUTH");
        }) as AxiosResponse;

    if (!response || response.status !== 200) {
      throw new UnauthorizedException('Cannot validate token');
    }

    console.log(response.data);

    return {
      access_token: response.data['access_token'],
      refresh_token: response.data['refresh_token'],
    }
  }

  public async loginOauth(params: OAuthLoginDto) {
    if (process.env.OAUTH2_ENABLE !== 'true') throw new BadRequestException("OAuth2.0/OIDC authentication not enabled!");

    const userinfoEndpoint = await this.getUserinfoEndpoint();

    const headersRequest = {
      'Authorization': `Bearer ${params.accessToken}`,
    };

    const response = await lastValueFrom(await this.httpService
        .get(userinfoEndpoint, { headers: headersRequest }))
        .catch((e) => Logger.log(e, "AUTH")) as AxiosResponse;

    if (!response || response.status !== 200) {
      throw new UnauthorizedException('Cannot validate token');
    }

    Logger.debug("Called userinfo endpoint", "AUTH");

    const email = response.data['email'];
    if (!email || email === "") throw new BadRequestException("User email not found", "AUTH");

    let user = await this.userRepository.findOne({ email: email });

    if (!user) {
      Logger.log("User does not exist, signing up", "AUTH");
      user = await this._signUp(email, false, null); // this _signUp should be moved in a service inside the immich auth module
    }

    return this._login(user);
  }

  private async getUserinfoEndpoint(): Promise<string> {
    if (this.oauthUserinfoEndpoint) return this.oauthUserinfoEndpoint;

    const endpoint = await this.fetchOauthEndpoint('userinfo_endpoint');
    if (endpoint) {
      this.oauthUserinfoEndpoint = endpoint;
      return this.oauthUserinfoEndpoint;
    }

    return undefined;
  }

  private async getTokenEndpoint(): Promise<string> {
    if (this.oauthTokenEndpoint) return this.oauthTokenEndpoint;

    const endpoint = await this.fetchOauthEndpoint('token_endpoint');
    if (endpoint) {
      this.oauthTokenEndpoint = endpoint;
      return this.oauthTokenEndpoint;
    }

    return undefined;
  }

  private async fetchOauthEndpoint(endpointId: string): Promise<string> {
    const response = await lastValueFrom(await this.httpService
        .get(process.env.OAUTH2_DISCOVERY_URL))
        .catch((e) => Logger.log(e, "AUTH")) as AxiosResponse;

    if (!response) return undefined;
    if (response.status !== 200) return undefined;

    Logger.debug(`Called discovery to get ${endpointId}`, "AUTH");
    const endpoint = response.data[endpointId];
    if (!endpoint) {
      Logger.debug(`${endpointId} not found`, "AUTH");
      return undefined;
    }

    return endpoint;
  }

}
