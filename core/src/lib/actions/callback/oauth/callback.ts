import * as checks from "./checks.js";
import * as o from "oauth4webapi";
import { OAuthCallbackError, OAuthProfileParseError, } from "../../../../errors.js";
/**
 * Handles the following OAuth steps.
 * https://www.rfc-editor.org/rfc/rfc6749#section-4.1.1
 * https://www.rfc-editor.org/rfc/rfc6749#section-4.1.3
 * https://openid.net/specs/openid-connect-core-1_0.html#UserInfoRequest
 *
 * @note Although requesting userinfo is not required by the OAuth2.0 spec,
 * we fetch it anyway. This is because we always want a user profile.
 */
function getURLSearchParameter(parameters, name) {
    const { 0: value, length } = parameters.getAll(name);
    if (length > 1) {
        throw new OPE(`"${name}" parameter must be provided only once`);
    }
    return value;
}
export async function handleOAuth(query, cookies, options, randomState) {
    console.log("handleOAuth");
    const { logger, provider } = options;
    let as;
    const { token, userinfo } = provider;
    console.log("token", token);
    console.log("userinfo", userinfo);
    // Falls back to authjs.dev if the user only passed params
    if ((!token?.url || token.url.host === "authjs.dev") &&
        (!userinfo?.url || userinfo.url.host === "authjs.dev")) {
        // We assume that issuer is always defined as this has been asserted earlier
        // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
        const issuer = new URL(provider.issuer);
        // console.log("issuer", issuer);
        const discoveryResponse = await o.discoveryRequest(issuer);
        // console.log("discoveryResponse", discoveryResponse);
        const discoveredAs = await o.processDiscoveryResponse(issuer, discoveryResponse);
        // console.log("discoveredAs", discoveredAs);
        if (!discoveredAs.token_endpoint)
            throw new TypeError("TODO: Authorization server did not provide a token endpoint.");
        if (!discoveredAs.userinfo_endpoint)
            throw new TypeError("TODO: Authorization server did not provide a userinfo endpoint.");
        as = discoveredAs;
    }
    else {
        as = {
            issuer: provider.issuer ?? "https://authjs.dev", // TODO: review fallback issuer
            token_endpoint: token?.url.toString(),
            userinfo_endpoint: userinfo?.url.toString(),
        };
    }
    const client = {
        client_id: provider.clientId,
        client_secret: provider.clientSecret,
        ...provider.client,
    };
    console.log("returned client", client);
    const resCookies = [];
    const state = await checks.state.use(cookies, resCookies, options, randomState);
    const codeGrantParams = o.validateAuthResponse(as, client, new URLSearchParams(query), provider.checks.includes("state") ? state : o.skipStateCheck);
    console.log("codeGrantParams", codeGrantParams);
    /** https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1 */
    if (o.isOAuth2Error(codeGrantParams)) {
        const cause = { providerId: provider.id, ...codeGrantParams };
        logger.debug("OAuthCallbackError", cause);
        throw new OAuthCallbackError("OAuth Provider returned an error", cause);
    }
    const codeVerifier = await checks.pkce.use(cookies, resCookies, options);
    let profile = {};
    let tokens;
    console.log("provider.type", provider.type);
    if (provider.type === "oidc") {
      let redirect_uri = provider.callbackUrl
      if (!options.isOnRedirectProxy && provider.redirectProxyUrl) {
        redirect_uri = provider.redirectProxyUrl
      }
      let codeGrantResponse = await o.authorizationCodeGrantRequest(
        as,
        client,
        codeGrantParams,
        redirect_uri,
        codeVerifier ?? "auth" // TODO: review fallback code verifier
      )
        
        const nonce = await checks.nonce.use(cookies, resCookies, options);
        const result = await o.processAuthorizationCodeOpenIDResponse(as, client, codeGrantResponse, nonce ?? o.expectNoNonce);
        if (o.isOAuth2Error(result)) {
            console.log("error", result);
            throw new Error("TODO: Handle OIDC response body error");
        }
        profile = o.getValidatedIdTokenClaims(result);
        tokens = result;
    }
    else {
        const tokenInfoUrl = 'https://authtest03.lkcoffee.com/v2/auth/token';
        const clientId = '1363ff06ae4c43461a6e';
        const clientSecret = '058e0626e80c2c4ea10e8afeaef51ec1d6a9cebd';
        const redirectUri = 'http://localhost:3010/api/auth/callback/lkcoffee';
        const userInfoUrl = 'https://authtest03.lkcoffee.com/v2/auth/userinfo';
        const code = getURLSearchParameter(codeGrantParams, 'code');
        console.log("code", code);
        const response = await fetch(tokenInfoUrl, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({
              client_id: clientId,
              client_secret: clientSecret,
              code,
              grant_type: 'authorization_code',
              redirect_uri: redirectUri,
            }).toString(),
          });
      
        if (!response.ok) {
        const errorText = await response.text();
        console.error('Failed to retrieve access token:', errorText);
        throw new Error(`Failed to retrieve access token: ${errorText}`);
        }
    
        const data = await response.json();
        tokens = data.data;
        console.log("data", data);
        const access_token = data.data?.access_token;
        console.log('access_token from token fetch:', access_token);
    
        if (!access_token) {
        throw new Error('Failed to retrieve access token');
        }
        if (userinfo?.request) {
            console.log("before userinfo.request");
            
            // const _profile = await userinfo.request({ tokens, provider });
            const userInfoResponse = await fetch(userInfoUrl, {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: new URLSearchParams({
                  access_token: access_token,
                  grant_type: 'access_token',
                }).toString(),
              });
          
              if (!userInfoResponse.ok) {
                const errorText = await userInfoResponse.text();
                console.error('Failed to retrieve user info:', errorText);
                throw new Error(`Failed to retrieve user info: ${errorText}`);
              }
          
            const userInfo = await userInfoResponse.json();
            console.log("_profile", userInfo);
            // if (_profile instanceof Object)
                // profile = _profile;
            if (userInfo instanceof Object)
                profile = userInfo;
            console.log("profile", profile);
        }
        else if (userinfo?.url) {
            console.log("before userinfoRequest");
            const userinfoResponse = await o.userInfoRequest(as, client, tokens.access_token);
            profile = await userinfoResponse.json();
            console.log("profile", profile);
        }
        else {
            throw new TypeError("No userinfo endpoint configured");
        }
    }
    
    
    if (tokens.expires_in) {
        tokens.expires_at =
            Math.floor(Date.now() / 1000) + Number(tokens.expires_in);
    }
    console.log('before getUserAndAccount');
    console.log('profile', profile);
    console.log('provider', provider);
    console.log("tokens", tokens);
    // console.log('access_token', access_token);
    const profileResult = await getUserAndAccount(profile, provider, tokens, logger); 
    console.log("profileResult", profileResult);
    return { ...profileResult, profile, cookies: resCookies };
}

// export async function handleOAuth(query, cookies, options, randomState) {

// }
/**
 * Returns the user and account that is going to be created in the database.
 * @internal
 */
export async function getUserAndAccount(OAuthProfile, provider, tokens, logger) {
    console.log("in getUserAndAccount");
    try {
        console.log('before provider.profile')
        const userFromProfile = await provider.profile(OAuthProfile, tokens);
        console.log('userFromProfile', userFromProfile);
        const user = {
            ...userFromProfile,
            id: crypto.randomUUID(),
            email: userFromProfile.email?.toLowerCase(),
        };
        return {
            user,
            account: {
                ...tokens,
                provider: provider.id,
                type: provider.type,
                providerAccountId: userFromProfile.id ?? crypto.randomUUID(),
            },
        };
    }
    catch (e) {
        // If we didn't get a response either there was a problem with the provider
        // response *or* the user cancelled the action with the provider.
        //
        // Unfortunately, we can't tell which - at least not in a way that works for
        // all providers, so we return an empty object; the user should then be
        // redirected back to the sign up page. We log the error to help developers
        // who might be trying to debug this when configuring a new provider.
        logger.debug("getProfile error details", OAuthProfile);
        logger.error(new OAuthProfileParseError(e, { provider: provider.id }));
    }
}
