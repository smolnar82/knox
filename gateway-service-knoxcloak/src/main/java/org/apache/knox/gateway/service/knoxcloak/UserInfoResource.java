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


import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.apache.knox.gateway.services.GatewayServices;
import org.apache.knox.gateway.services.ServiceType;
import org.apache.knox.gateway.services.security.token.TokenMetadata;
import org.apache.knox.gateway.services.security.token.TokenStateService;
import org.apache.knox.gateway.services.security.token.UnknownTokenException;
import org.apache.knox.gateway.util.JsonUtils;
import org.apache.knox.gateway.util.knoxcloak.KnoxcloakUtils;
import org.apache.knox.gateway.util.knoxcloak.FederatedOpConfiguration;

import javax.annotation.PostConstruct;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.apache.knox.gateway.util.knoxcloak.KnoxcloakConstants.BASE_RESORCE_PATH;
import static org.apache.knox.gateway.util.knoxcloak.KnoxcloakUtils.error;


@Path(UserInfoResource.RESOURCE_PATH)
@Produces(MediaType.APPLICATION_JSON)
public class UserInfoResource {

    static final String RESOURCE_PATH = BASE_RESORCE_PATH + "/userinfo";
    private FederatedOpConfiguration federatedOpConfiguration;
    private UserParamsProvider userParamsProvider;

    @Context
    private ServletContext servletContext;

    @Context
    private HttpServletRequest request;

    @PostConstruct
    public void init() {
        this.federatedOpConfiguration = new FederatedOpConfiguration(servletContext);
        this.userParamsProvider = new LdapUserParamsProvider(servletContext.getInitParameter("user.params.provider.ldap.url"));
    }

    public Response doGet() {
        try {
            return getUserInfo();
        } catch (UnknownTokenException e) {
            throw new RuntimeException(e);
        }
    }

    public Response doPost() {
        throw new UnsupportedOperationException();
    }

    @GET
    public Response getUserInfo() throws UnknownTokenException {
        final String tokenId = request.getAttribute("X-Token-Id") == null ? null : request.getAttribute("X-Token-Id").toString();
        if (tokenId == null) {
            return error("Invalid request", "Cannot find tokenId");
        }
        final String scope = request.getAttribute("X-Token-Scope") == null ? "" :  request.getAttribute("X-Token-Scope").toString();
        final TokenMetadata tokenMetadata = getReadonlyTokenStateService().getTokenMetadata(tokenId);
        final Map<String, Object> userInfo =  userParamsProvider.getParamsFor(tokenMetadata.getUserName(), scope);

        if (federatedOpConfiguration.isFederatedOpRedirectEnabled()) {
            final String federatedAccessToken = KnoxcloakUtils.joinFederatedAccessToken(tokenMetadata.getMetadataMap());
            final Map<String, Object> federatedUserInfo = redirectToFederatedOp(federatedAccessToken);
            if (!federatedUserInfo.isEmpty()) {
                userInfo.put("federation", federatedUserInfo);
            }
        }

        return Response.ok(JsonUtils.renderAsJsonString(userInfo, true)).build();
    }

    private TokenStateService getReadonlyTokenStateService() {
        GatewayServices services = (GatewayServices) servletContext.getAttribute(GatewayServices.GATEWAY_SERVICES_ATTRIBUTE);
        return services.getService(ServiceType.TOKEN_STATE_SERVICE);
    }

    private Map<String, Object> redirectToFederatedOp(final String federatedAccessToken) {
        try (CloseableHttpClient client = HttpClients.createDefault()) {
            final HttpGet get = new HttpGet(federatedOpConfiguration.getUserInfoEndpoint());
            get.setHeader("Authorization", "Bearer " + federatedAccessToken);

            try (CloseableHttpResponse response = client.execute(get)) {
                final String json = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
                final Map<String, Object> rawClaims = new ObjectMapper().readValue(json, new TypeReference<Map<String, Object>>() {
                });

                final Map<String, Object> normalized = new HashMap<>();
                normalized.put("sub", rawClaims.get("sub"));
                normalized.put("email", rawClaims.get("email"));
                normalized.put("name", rawClaims.get("name"));
                normalized.put("preferred_username", rawClaims.get("preferred_username"));
                normalized.put("given_name", rawClaims.get("given_name"));
                normalized.put("family_name", rawClaims.get("family_name"));
                normalized.put("email_verified", rawClaims.get("email_verified"));

                final Map<String, Object> realmAccess = (Map<String, Object>) rawClaims.get("realm_access");
                if (realmAccess != null && realmAccess.get("roles") instanceof Iterable) {
                    normalized.put("roles", realmAccess.get("roles"));
                } else {
                    normalized.put("roles", Collections.emptyList());
                }

                final Map<String, Object> resourceAccess = (Map<String, Object>) rawClaims.get("resource_access");
                if (resourceAccess != null && resourceAccess.get("account") instanceof Map) {
                    Map<String, Object> accountRoles = (Map<String, Object>) resourceAccess.get("account");
                    normalized.put("account_roles", accountRoles.get("roles"));
                } else {
                    normalized.put("account_roles", Collections.emptyList());
                }

                return normalized;
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}

