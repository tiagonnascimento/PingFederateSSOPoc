/**
 * Plugin customizado para Auth Provider Ping Federate.
 * Permite enviar o header 'app-key' nas requisições ao token endpoint.
 */
global class PingFederateAuthProviderPlugin extends Auth.AuthProviderPluginClass {

    global String getCustomMetadataType() {
        return 'PingFederateAuthConfig__mdt';
    }

    global PageReference initiate(Map<String, String> config, String state) {
        String authorizeUrl = config.get('Authorize_URL__c');
        String clientId = config.get('Consumer_Key__c');
        String redirectUri = getCallbackUrl(config);
        String scopes = config.get('Scopes__c');
        if (String.isBlank(scopes)) {
            scopes = 'openid';
        }

        // PKCE: code_verifier e code_challenge (S256)
        // Armazenamos code_verifier no cache - o state deve permanecer intacto para validação do Salesforce
        String codeVerifier = generateCodeVerifier();
        String codeChallenge = generateCodeChallenge(codeVerifier);
        Cache.OrgPartition orgPart = Cache.Org.getPartition('PKCEPartition');
        if (orgPart == null) {
            throw new Auth.AuthProviderPluginException('Platform Cache partition PKCEPartition not found. Create it in Setup > Platform Cache.');
        }
        String cacheKey = buildPkceCacheKey(state);
        orgPart.put(cacheKey, codeVerifier, 600);

        String authUrl = authorizeUrl + '?' +
            'response_type=code' +
            '&client_id=' + EncodingUtil.urlEncode(clientId, 'UTF-8') +
            '&redirect_uri=' + EncodingUtil.urlEncode(redirectUri, 'UTF-8') +
            '&scope=' + EncodingUtil.urlEncode(scopes, 'UTF-8') +
            '&state=' + EncodingUtil.urlEncode(state, 'UTF-8');
            // '&code_challenge=' + EncodingUtil.urlEncode(codeChallenge, 'UTF-8') +
            // '&code_challenge_method=S256';

        return new PageReference(authUrl);
    }

    global Auth.AuthProviderTokenResponse handleCallback(Map<String, String> config, Auth.AuthProviderCallbackState state) {
        Map<String, String> queryParams = state.queryParameters != null ? state.queryParameters : new Map<String, String>();
        String code = queryParams.get('code');
        String stateParam = queryParams.get('state');

        if ((String.isBlank(code) || String.isBlank(stateParam)) && state.body != null && String.isNotBlank(state.body)) {
            Map<String, String> bodyParams = parseFormUrlEncoded(state.body);
            if (String.isBlank(code)) {
                code = bodyParams.get('code');
            }
            if (String.isBlank(stateParam)) {
                stateParam = bodyParams.get('state');
            }
        }

        if (String.isBlank(code)) {
            throw new Auth.AuthProviderPluginException('Authorization code not found in callback');
        }
        if (String.isBlank(stateParam)) {
            throw new Auth.AuthProviderPluginException('State parameter not found in callback');
        }

        stateParam = stateParam.trim();
        String codeVerifier = '';
        Cache.OrgPartition orgPart = Cache.Org.getPartition('PKCEPartition');
        if (orgPart != null) {
            String cacheKey = buildPkceCacheKey(stateParam);
            codeVerifier = (String) orgPart.get(cacheKey);
            if (String.isNotBlank(codeVerifier)) {
                codeVerifier = codeVerifier.trim();
                orgPart.remove(cacheKey);
            }
        }
        if (String.isBlank(codeVerifier)) {
            throw new Auth.AuthProviderPluginException('PKCE code_verifier not found. Ensure Platform Cache partition PKCEPartition exists and has capacity.');
        }
        String salesforceState = stateParam;

        String tokenUrl = config.get('Token_URL__c');
        String clientId = config.get('Consumer_Key__c');
        String clientSecret = config.get('Consumer_Secret__c');
        String redirectUri = getCallbackUrl(config);

        String body = 'grant_type=authorization_code' +
            '&code=' + EncodingUtil.urlEncode(code, 'UTF-8') +
            '&redirect_uri=' + EncodingUtil.urlEncode(redirectUri, 'UTF-8');
            // '&code_verifier=' + EncodingUtil.urlEncode(codeVerifier, 'UTF-8');

        HttpRequest req = new HttpRequest();
        req.setEndpoint(tokenUrl);
        req.setMethod('POST');
        req.setHeader('Content-Type', 'application/x-www-form-urlencoded');
        req.setHeader('Accept', 'application/json');
        req.setHeader('Authorization', 'Basic ' + EncodingUtil.base64Encode(Blob.valueOf(clientId + ':' + clientSecret)));
        req.setBody(body);
        req.setTimeout(120000);

        // Header customizado app-key
        String appKey = config.get('App_Key__c');
        if (String.isNotBlank(appKey)) {
            req.setHeader('app-key', appKey);
        }

        Http http = new Http();
        HttpResponse res = http.send(req);
        System.debug('Response Body: ' + res.getBody());


        if (res.getStatusCode() != 200) {
            throw new Auth.AuthProviderPluginException('Token request failed: ' + res.getStatusCode() + ' - ' + res.getStatus());
        }

        Map<String, Object> tokenData = (Map<String, Object>) JSON.deserializeUntyped(res.getBody());
        String accessToken = (String) tokenData.get('access_token');
        String refreshToken = (String) tokenData.get('refresh_token');
        String idToken = (String) tokenData.get('id_token');

        String providerName = config.get('Provider__c');
        return new Auth.AuthProviderTokenResponse(providerName, accessToken, refreshToken != null ? refreshToken : '', salesforceState, idToken);
    }

    global Auth.UserData getUserInfo(Map<String, String> config, Auth.AuthProviderTokenResponse response) {
        String idToken = response.idToken;
        if (String.isBlank(idToken)) {
            throw new Auth.AuthProviderPluginException('id_token is required for user matching');
        }

        Map<String, Object> claims = decodeIdTokenPayload(idToken);
        String sub = (String) claims.get('sub');
        if (String.isBlank(sub)) {
            throw new Auth.AuthProviderPluginException('sub claim is required in id_token for user matching');
        }
        sub = sub.trim();

        String firstName = (String) claims.get('given_name');
        String lastName = (String) claims.get('family_name');
        String email = (String) claims.get('email');
        String fullName = (String) claims.get('name');

        Map<String, String> attrMap = new Map<String, String>{ 'sfdc_federationid' => sub };
        return new Auth.UserData(
            sub,
            firstName,
            lastName,
            fullName,
            email,
            null,
            sub,
            null,
            null,
            null,
            attrMap
        );
    }

    private Map<String, Object> decodeIdTokenPayload(String idToken) {
        List<String> parts = idToken.split('\\.');
        if (parts.size() < 2) {
            throw new Auth.AuthProviderPluginException('Invalid id_token format');
        }
        String payloadB64 = parts[1];
        String payloadJson = base64UrlDecode(payloadB64);
        return (Map<String, Object>) JSON.deserializeUntyped(payloadJson);
    }

    private String base64UrlDecode(String base64Url) {
        String base64 = base64Url.replace('-', '+').replace('_', '/');
        Integer padding = 4 - Math.mod(base64.length(), 4);
        if (padding != 4) {
            for (Integer i = 0; i < padding; i++) {
                base64 += '=';
            }
        }
        Blob decoded = EncodingUtil.base64Decode(base64);
        return decoded.toString();
    }

    private String getCallbackUrl(Map<String, String> config) {
        return URL.getOrgDomainUrl().toExternalForm() + '/services/authcallback/' + config.get('Provider__c');
    }

    private String generateCodeVerifier() {
        Blob randomBlob = Crypto.generateAesKey(256);
        return EncodingUtil.base64Encode(randomBlob).replace('+', '-').replace('/', '_').replace('=', '');
    }

    private String generateCodeChallenge(String codeVerifier) {
        Blob challengeBlob = Crypto.generateDigest('SHA-256', Blob.valueOf(codeVerifier));
        return EncodingUtil.base64Encode(challengeBlob).replace('+', '-').replace('/', '_').replace('=', '');
    }

    private String buildPkceCacheKey(String state) {
        String hash = EncodingUtil.convertToHex(Crypto.generateDigest('SHA-256', Blob.valueOf(state)));
        return hash.length() >= 50 ? hash.substring(0, 50) : hash;
    }

    private Map<String, String> parseFormUrlEncoded(String body) {
        Map<String, String> params = new Map<String, String>();
        if (String.isBlank(body)) {
            return params;
        }
        for (String pair : body.split('&')) {
            List<String> kv = pair.split('=', 2);
            if (kv.size() == 2) {
                params.put(EncodingUtil.urlDecode(kv[0], 'UTF-8'), EncodingUtil.urlDecode(kv[1], 'UTF-8'));
            }
        }
        return params;
    }

    global override Auth.OAuthRefreshResult refresh(Map<String, String> config, String refreshToken) {
        if (String.isBlank(refreshToken)) {
            throw new Auth.AuthProviderPluginException('Refresh token is required');
        }

        String tokenUrl = config.get('Token_URL__c');
        String clientId = config.get('Consumer_Key__c');
        String clientSecret = config.get('Consumer_Secret__c');

        String body = 'grant_type=refresh_token' +
            '&refresh_token=' + EncodingUtil.urlEncode(refreshToken, 'UTF-8');

        HttpRequest req = new HttpRequest();
        req.setEndpoint(tokenUrl);
        req.setMethod('POST');
        req.setHeader('Content-Type', 'application/x-www-form-urlencoded');
        req.setHeader('Accept', 'application/json');
        req.setHeader('Authorization', 'Basic ' + EncodingUtil.base64Encode(Blob.valueOf(clientId + ':' + clientSecret)));
        req.setBody(body);
        req.setTimeout(120000);

        String appKey = config.get('App_Key__c');
        if (String.isNotBlank(appKey)) {
            req.setHeader('app-key', appKey);
        }

        Http http = new Http();
        HttpResponse res = http.send(req);

        if (res.getStatusCode() != 200) {
            throw new Auth.AuthProviderPluginException('Refresh token request failed: ' + res.getStatusCode());
        }

        Map<String, Object> tokenData = (Map<String, Object>) JSON.deserializeUntyped(res.getBody());
        String accessToken = (String) tokenData.get('access_token');
        String tokenType = (String) tokenData.get('token_type');
        if (String.isBlank(tokenType)) {
            tokenType = 'Bearer';
        }

        return new Auth.OAuthRefreshResult(accessToken, tokenType);
    }
}
