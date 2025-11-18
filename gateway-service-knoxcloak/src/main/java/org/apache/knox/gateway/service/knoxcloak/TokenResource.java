/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with this
 * work for additional information regarding copyright ownership. The ASF
 * licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.apache.knox.gateway.service.knoxcloak;

import com.nimbusds.jose.KeyLengthException;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.apache.knox.gateway.service.knoxtoken.PasscodeTokenResourceBase;
import org.apache.knox.gateway.services.ServiceLifecycleException;
import org.apache.knox.gateway.services.security.AliasServiceException;
import org.apache.knox.gateway.services.security.token.TokenMetadata;
import org.apache.knox.gateway.services.security.token.UnknownTokenException;
import org.apache.knox.gateway.util.JsonUtils;
import org.apache.knox.gateway.util.knoxcloak.KnoxcloakUtils;
import org.apache.knox.gateway.util.knoxcloak.FederatedOpConfiguration;

import javax.annotation.PostConstruct;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.apache.knox.gateway.util.knoxcloak.KnoxcloakConstants.BASE_RESORCE_PATH;
import static org.apache.knox.gateway.util.knoxcloak.KnoxcloakUtils.error;

@Path(TokenResource.RESOURCE_PATH)
@Produces(MediaType.APPLICATION_JSON)
public class TokenResource extends PasscodeTokenResourceBase {
    static final String RESOURCE_PATH = BASE_RESORCE_PATH + "/token";
    private FederatedOpConfiguration federatedOpConfiguration;
    private UserParamsProvider userParamsProvider;

    @Context
    private HttpServletRequest request;

    @Context
    private ServletContext servletContext;

    @PostConstruct
    @Override
    public void init() throws ServletException, AliasServiceException, ServiceLifecycleException, KeyLengthException {
        super.init();
        this.servletContext = wrapContextForDefaultParams(this.servletContext);
        this.federatedOpConfiguration = new FederatedOpConfiguration(servletContext);
        this.userParamsProvider = new LdapUserParamsProvider(servletContext.getInitParameter("user.params.provider.ldap.url"));
    }

    @Override
    @POST
    public Response doPost() {
        final String code = request.getParameter("code");
        final String redirectUri = request.getParameter("redirect_uri");

        final Response paramVerificationErrorResponse = verifyParams(code, redirectUri);
        if (paramVerificationErrorResponse == null) {
            try {
                final String federatedAuthCode = validateAuthCode(code, redirectUri);
                String federatedAccessToken = null;
                if (federatedOpConfiguration.isFederatedOpRedirectEnabled()) {
                    if (federatedAuthCode == null) {
                        return error("Federated OP Auth Error", "Expected federated auth code, but not found");
                    }
                    final Response federatedTokenExchangeResponse = redirectToFederatedOp(federatedAuthCode, federatedOpConfiguration.getAuthorizeCallback());
                    if (federatedTokenExchangeResponse.getStatus() == Response.Status.OK.getStatusCode()) {
                        final Map<String, String> federatedTokenExchangeResponseBodyMap = JsonUtils.getMapFromJsonString((String) federatedTokenExchangeResponse.getEntity());
                        federatedAccessToken =  federatedTokenExchangeResponseBodyMap.get("access_token");
                    } else {
                        return federatedTokenExchangeResponse;
                    }
                }

                final Response knoxTokenExchangeResponse = getAuthenticationToken();
                final Map<String, String> knoxTokenExchangeResponseMap = JsonUtils.getMapFromJsonString(knoxTokenExchangeResponse.getEntity().toString());
                final String tokenId = knoxTokenExchangeResponseMap.get("token_id");
                if (federatedAccessToken != null) {
                    final TokenMetadata tokenMetadata = tokenStateService.getTokenMetadata(tokenId);
                    KnoxcloakUtils.splitFederatedAccessToken(federatedAccessToken).forEach(tokenMetadata::add);
                    tokenStateService.addMetadata(tokenId, tokenMetadata);
                }
                return knoxTokenExchangeResponse;
            } catch (AuthTokenValidationError e) {
                return error("Auth code validation error", e.getMessage());
            } catch (UnknownTokenException e) {
                throw new RuntimeException(e);
            } finally {
                try {
                    tokenStateService.revokeToken(code);
                } catch (UnknownTokenException e) {
                    //NOP: this should have been handled by the above UnknownTokenException already
                }
            }
        }
        return paramVerificationErrorResponse;
    }

    @Override
    protected UserContext buildUserContext(HttpServletRequest request) {
        try {
            final String code = request.getParameter("code");
            final TokenMetadata tokenMetadata = tokenStateService.getTokenMetadata(code);
            final String scope = tokenMetadata.getMetadata("scope");
            final Map<String, Object> userParams = userParamsProvider.getParamsFor(tokenMetadata.getUserName(), scope);
            userParams.put("scope", scope);
            return new UserContext(tokenMetadata.getUserName(), null, userParams);
        } catch (UnknownTokenException e) {
            //this should not happen as we have just validated the auth code
            throw new RuntimeException(e);
        }
    }

    @Override
    protected Response getAuthenticationToken() {
        final Response authTokenResponse = super.getAuthenticationToken();
        if (Response.Status.OK.getStatusCode() == authTokenResponse.getStatus()) {
            final Map<String, String> responseMap = JsonUtils.getMapFromJsonString(authTokenResponse.getEntity().toString());
            final String passcode = responseMap.get(ACCESS_TOKEN);
            responseMap.remove(PASSCODE);
            responseMap.put("id_token", passcode);
                return Response.ok().entity(JsonUtils.renderAsJsonString(responseMap)).build();
        }
        return authTokenResponse;
    }

    private Response verifyParams(String code, String redirectUri) {
        if (code == null || code.isEmpty()) {
            return error("invalid_request", "Missing code");
        }

        if (redirectUri == null || redirectUri.isEmpty()) {
            return error("invalid_request", "Missing redirect_uri");
        }

        return null;
    }

    private String validateAuthCode(String code, String redirectUri) throws AuthTokenValidationError {
        try {
            final TokenMetadata tokenMetadata = tokenStateService.getTokenMetadata(code);
            final String associatedClientId = tokenMetadata.getMetadata("client_id");
            final String associateRedirectUri = tokenMetadata.getMetadata("redirect_uri");
            if (!tokenMetadata.isOneTimeOnly()) {
                throw new AuthTokenValidationError("Invalid auth_code: not a one-time-only token");
            } else if (!tokenMetadata.isAuthCode()) {
                throw new AuthTokenValidationError("Invalid auth_code: not an auth code token"); //this one or the previous one might be redundant
            } else if (tokenStateService.getTokenExpiration(code) <= System.currentTimeMillis()) {
                throw new AuthTokenValidationError("Invalid auth_code: expired");
            } else if (!associateRedirectUri.equals(redirectUri)) {
                throw new AuthTokenValidationError("Invalid redirect_uri: " + redirectUri);
            } else {
                final String clientId = request.getParameter("client_id");
                if (!associatedClientId.equals(clientId)) {
                    throw new AuthTokenValidationError("Invalid client_id: " + clientId);
                }
            }
            return tokenMetadata.getMetadata("federated_auth_code");
        } catch (UnknownTokenException e) {
            throw new AuthTokenValidationError("Unknown auth_code");
        }
    }

    private Response redirectToFederatedOp(final String code, final String redirectUri) {
        final List<NameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair("code", code));
        params.add(new BasicNameValuePair("redirect_uri", redirectUri));
        params.add(new BasicNameValuePair("grant_type", "authorization_code"));
        params.add(new BasicNameValuePair("client_id", federatedOpConfiguration.getClientId()));
        params.add(new BasicNameValuePair("client_secret", federatedOpConfiguration.getClientSecret()));

        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpPost post = new HttpPost(federatedOpConfiguration.getTokenEndpoint());
            post.setHeader("Content-Type", "application/x-www-form-urlencoded");
            post.setEntity(new UrlEncodedFormEntity(params, StandardCharsets.UTF_8));

            try (CloseableHttpResponse response = httpClient.execute(post)) {
                int status = response.getStatusLine().getStatusCode();
                String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
                return Response.status(status).entity(body).build();
            }
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("{\"error\":\"" + e.getMessage() + "\"}").build();
        }
    }

    private static class AuthTokenValidationError extends Exception {
        AuthTokenValidationError(String message) {
            super(message);
        }
    }
}
