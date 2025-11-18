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
import org.apache.commons.lang3.StringUtils;
import org.apache.knox.gateway.security.SubjectUtils;
import org.apache.knox.gateway.service.knoxtoken.PasscodeTokenResourceBase;
import org.apache.knox.gateway.services.ServiceLifecycleException;
import org.apache.knox.gateway.services.security.AliasServiceException;
import org.apache.knox.gateway.services.security.token.TokenMetadata;
import org.apache.knox.gateway.services.security.token.TokenMetadataType;
import org.apache.knox.gateway.services.security.token.UnknownTokenException;
import org.apache.knox.gateway.util.JsonUtils;
import org.apache.knox.gateway.util.knoxcloak.AuthorizeRequestMetadata;
import org.apache.knox.gateway.util.knoxcloak.AuthorizeRequestMetadataStore;

import javax.annotation.PostConstruct;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.apache.knox.gateway.util.knoxcloak.KnoxcloakConstants.BASE_RESORCE_PATH;
import static org.apache.knox.gateway.util.knoxcloak.KnoxcloakConstants.DEFAULT_SCOPES;
import static org.apache.knox.gateway.util.knoxcloak.KnoxcloakUtils.error;


@Path(AuthorizeResource.RESOURCE_PATH)
public class AuthorizeResource extends PasscodeTokenResourceBase {
    static final String RESOURCE_PATH = BASE_RESORCE_PATH + "/authorize";

    private static final String UTF_8 = StandardCharsets.UTF_8.name();

    private AuthorizeRequestMetadataStore authorizeRequestMetadataStore;

    @Context
    private HttpServletRequest request;

    @Context
    private ServletContext servletContext;

    @PostConstruct
    @Override
    public void init() throws ServletException, AliasServiceException, ServiceLifecycleException, KeyLengthException {
        super.init();
        this.authorizeRequestMetadataStore = AuthorizeRequestMetadataStore.getInstance(tokenTTL);
    }

    @GET
    public Response authorize(@QueryParam("response_type") String responseType,
                              @QueryParam("client_id") String clientId,
                              @QueryParam("redirect_uri") String redirectUri,
                              @QueryParam("scope") String scope,
                              @QueryParam("state") String state,
                              @QueryParam("nonce") String nonce) throws Exception {
        final String subject = SubjectUtils.getCurrentEffectivePrincipalName();
        final Set<String> requestedScopes = StringUtils.isBlank(scope) ? DEFAULT_SCOPES : new HashSet<>(Arrays.asList(scope.split("\\s+")));
        final AuthorizeRequestMetadata authorizeRequestMetadata = new AuthorizeRequestMetadata(clientId, subject, responseType, redirectUri, requestedScopes, state, nonce);
        final Response verificationErrorResponse = verifyParams(authorizeRequestMetadata);
        if (verificationErrorResponse != null) {
            return verificationErrorResponse;
        }

        if (!hasConsent(authorizeRequestMetadata)) {
            if ("true".equalsIgnoreCase(request.getParameter("auto_consent"))) {
                markConsentAccepted(authorizeRequestMetadata);
            } else {
                final String consentAuthState = UUID.randomUUID().toString();
                authorizeRequestMetadataStore.storeRequestMetadata(consentAuthState, authorizeRequestMetadata);
                final String baseUri = servletContext.getContextPath() + "/authConsent";
                final String scopeParam = URLEncoder.encode(authorizeRequestMetadata.getJoinedRequestedScopes(), StandardCharsets.UTF_8.name());
                final String redirect = String.format(Locale.US, "%s?client_id=%s&state=%s&scope=%s", baseUri, clientId, consentAuthState, scopeParam);
                return Response.seeOther(java.net.URI.create(redirect)).build();
            }
        }
        return getAuthCodeFromKnox(authorizeRequestMetadata, null);
    }

    private boolean hasConsent(final AuthorizeRequestMetadata authorizeRequestMetadata) {
        try {
            final TokenMetadata tokenMetadata = tokenStateService.getTokenMetadata(authorizeRequestMetadata.getClientId());
            final String consentKey = "consentAccepted_" + authorizeRequestMetadata.getSubject();
            final String storedScopes = tokenMetadata.getMetadataMap().get(consentKey);
            if (storedScopes == null || storedScopes.isEmpty()) {
                return false;
            }
            final Set<String> storedScopeSet = new HashSet<>(Arrays.asList(storedScopes.split("\\s+")));
            return storedScopeSet.containsAll(authorizeRequestMetadata.getRequestedScopes());
        } catch (UnknownTokenException e) {
            //this should not happen as we validated the client_id already
            return false;
        }
    }

    private void markConsentAccepted(AuthorizeRequestMetadata authorizeRequestMetadata) {
        final TokenMetadata consentAcceptedMetadata = new TokenMetadata();
        consentAcceptedMetadata.add("consentAccepted_" + authorizeRequestMetadata.getSubject(), authorizeRequestMetadata.getJoinedRequestedScopes());
        tokenStateService.addMetadata(authorizeRequestMetadata.getClientId(), consentAcceptedMetadata);
    }

    private Response getAuthCodeFromKnox(final AuthorizeRequestMetadata authorizeRequestMetadata, final String federatedAuthCode) throws Exception {
        final Response tokenResponse = getAuthenticationToken();
        if (tokenResponse.getStatus() == Response.Status.OK.getStatusCode()) {
            final Map<String, String> tokenResponseMap = JsonUtils.getMapFromJsonString(tokenResponse.getEntity().toString());
            final String tokenId = tokenResponseMap.get(TOKEN_ID);
            decorateAuthCodeToken(tokenId, authorizeRequestMetadata, federatedAuthCode);
            return redirectToAuthSuccess(authorizeRequestMetadata, tokenId);
        }
        return tokenResponse;
    }

    private Response redirectToAuthSuccess(final AuthorizeRequestMetadata authorizeRequestMetadata, final String code) throws UnsupportedEncodingException {
        final String redirectLocation = authorizeRequestMetadata.getRedirectUri()
                + "?code=" + URLEncoder.encode(code, UTF_8)
                + "&state=" + URLEncoder.encode(authorizeRequestMetadata.getState(), UTF_8);
        return Response.seeOther(URI.create(redirectLocation)).build();
    }

    @GET
    @Path("/callback")
    public Response authCallback() throws Exception {
        //This is the callback for the federated OP
        final String federatedAuthCode = request.getParameter("code");
        final String state = request.getParameter("state");
        final AuthorizeRequestMetadata authorizeRequestMetadata = authorizeRequestMetadataStore.getRequestMetadata(state);
        //TODO: exchange federated auth code to ID Token + access token
        return getAuthCodeFromKnox(authorizeRequestMetadata, federatedAuthCode);
    }

    @GET
    @Path("/consentAccepted")
    public Response consentAccepted() throws Exception {
        final String state = request.getParameter("state");
        final AuthorizeRequestMetadata authorizeRequestMetadata = authorizeRequestMetadataStore.getRequestMetadata(state);
        if (authorizeRequestMetadata == null) {
            return error("Consent cannot be accepted", "Invalid state");
        }
        markConsentAccepted(authorizeRequestMetadata);
        return authorize(authorizeRequestMetadata.getResponseType(),
                authorizeRequestMetadata.getClientId(),
                authorizeRequestMetadata.getRedirectUri(),
                authorizeRequestMetadata.getJoinedRequestedScopes(),
                authorizeRequestMetadata.getState(),
                authorizeRequestMetadata.getNonce());
    }

    @GET
    @Path("/consentDenied")
    public Response consentDenied() throws Exception {
        return Response.status(Response.Status.FORBIDDEN).entity("Consent denied!").build();
    }

    private void decorateAuthCodeToken(final String tokenId, final AuthorizeRequestMetadata authorizeRequestMetadata, final String federatedAuthCode) throws Exception {
        final Map<String, String> authCodeTokenMap = new HashMap<>();
        authCodeTokenMap.put(TokenMetadata.TYPE, TokenMetadataType.AUTH_CODE.name());
        authCodeTokenMap.put(TokenMetadata.ONE_TIME_ONLY, "true");
        authCodeTokenMap.put("client_id", authorizeRequestMetadata.getClientId());
        authCodeTokenMap.put("redirect_uri", authorizeRequestMetadata.getRedirectUri());
        authCodeTokenMap.put("userName", authorizeRequestMetadata.getSubject());
        authCodeTokenMap.put("scope", authorizeRequestMetadata.getJoinedRequestedScopes());
        if (federatedAuthCode != null) {
            authCodeTokenMap.put("federated_auth_code", federatedAuthCode);
        }
        tokenStateService.addMetadata(tokenId, new TokenMetadata(authCodeTokenMap));
    }

    private Response verifyParams(final AuthorizeRequestMetadata authorizeRequestMetadata) {
        final Response basicVerificationResponse = authorizeRequestMetadata.verify();
        if (basicVerificationResponse == null) {
            final TokenMetadata tokenMetadata;
            // Verify client ID
            try {
                //This is ok for a POC, but we should cache that later
                tokenMetadata = tokenStateService.getTokenMetadata(authorizeRequestMetadata.getClientId());
            } catch (UnknownTokenException e) {
                return error("invalid_request", "Unknown client_id");
            }

            // Verify redirect URI
            final String storedRedirectUris = tokenMetadata.getMetadata("redirect_uris");
            if (StringUtils.isBlank(storedRedirectUris)) {
                return error("invalid_request", "Missing stored redirect_uris, cannot authorize the request");
            }
            final Set<String> registeredRedirectUris = new HashSet<>(Arrays.asList(storedRedirectUris.split(",")));
            if (!matchesRedirectUri(authorizeRequestMetadata.getRedirectUri(), registeredRedirectUris)) {
                return error("invalid_request", "Invalid redirect_uri");
            }

            // Verify scope(s)
            final String storedAllowedScopes = tokenMetadata.getMetadata("allowed_scopes");
            if (StringUtils.isBlank(storedAllowedScopes)) {
                return error("invalid_scope", "Missing stored allowed_scopes, cannot authorize the request");
            }
            final Set<String> registeredScopes = new HashSet<>(Arrays.asList(storedAllowedScopes.trim().split("\\s+")));
            if (authorizeRequestMetadata.getRequestedScopes().stream().anyMatch(scope -> !registeredScopes.contains(scope))) {
                return error("invalid_scope", "One or more requested scopes are not allowed");
            }

            return null;
        }
        return basicVerificationResponse;
    }

    private boolean matchesRedirectUri(String requestedUri, Set<String> registeredUris) {
        for (String registered : registeredUris) {
            if (registered.endsWith("*")) {
                String prefix = registered.substring(0, registered.length() - 1);
                if (requestedUri.startsWith(prefix)) {
                    return true;
                }
            } else if (registered.equals(requestedUri)) {
                return true;
            }
        }
        return false;
    }
}
