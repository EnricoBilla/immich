import {ExecutionContext, Injectable, Logger} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import {Observable} from "rxjs";
import * as util from "util";

@Injectable()
export class Oauth2AuthGuard extends AuthGuard('oauth2') {

    canActivate(context: ExecutionContext): boolean | Promise<boolean> | Observable<boolean> {
        const request = context.switchToHttp().getRequest();
        //Logger.log(util.inspect(request));
        return super.canActivate(context);
    }
}