import 'package:flutter_appauth/flutter_appauth.dart';

const FlutterAppAuth appAuth = FlutterAppAuth();

// todo retrieve from immich
const OAUTH2_ISSUER = 'https://authentik.local/application/o/immichapp/';
const OAUTH2_CLIENT_ID = 'client_id';
const OAUTH2_REDIRECT_URI = 'app.alextran.immich://login-callback';

class OAuth2Provider {
  
  Future<AuthorizationTokenResponse?> getToken() async {
    return await appAuth.authorizeAndExchangeCode(
      AuthorizationTokenRequest(
        OAUTH2_CLIENT_ID,
        OAUTH2_REDIRECT_URI,
        issuer: OAUTH2_ISSUER,
        scopes: ['openid','profile', 'email'],
      ),
    );

  }

}