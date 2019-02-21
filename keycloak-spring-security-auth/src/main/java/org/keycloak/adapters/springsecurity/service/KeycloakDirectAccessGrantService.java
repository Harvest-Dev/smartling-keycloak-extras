/*
 * Copyright 2015 Smartling, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.adapters.springsecurity.service;

import org.keycloak.OAuth2Constants;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.RefreshableKeycloakSecurityContext;
import org.keycloak.adapters.springsecurity.service.context.KeycloakConfidentialClientRequestFactory;
import org.keycloak.adapters.springsecurity.support.KeycloakSpringAdapterUtils;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.AccessTokenResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import javax.annotation.PostConstruct;
import java.util.ArrayList;
import java.util.Arrays;

/**
 * Supports Keycloak's direct access grants API using direct REST invocations to obtain
 * an access token.
 *
 * @author <a href="mailto:srossillo@smartling.com">Scott Rossillo</a>
 */
@Component
public class KeycloakDirectAccessGrantService implements DirectAccessGrantService {

    protected RestTemplate template;

    @Autowired
    private KeycloakDeployment keycloakDeployment;
    @Autowired
    private KeycloakConfidentialClientRequestFactory requestFactory;

    @PostConstruct
    public void init() {
        template = new RestTemplate(requestFactory);
    }

    @Override
    public RefreshableKeycloakSecurityContext login(String username, String password) throws VerificationException {

        ArrayList<KeyValuePair> bodyParams = new ArrayList<>();
        bodyParams.add(new KeyValuePair("username", username));
        bodyParams.add(new KeyValuePair("password", password));
        bodyParams.add(new KeyValuePair("scope", "openid"));
        bodyParams.add(new KeyValuePair(OAuth2Constants.GRANT_TYPE, OAuth2Constants.PASSWORD));

        AccessTokenResponse response = template.postForObject(keycloakDeployment.getTokenUrl(),
                new HttpEntity<>(createBody(bodyParams), createHeaders()), AccessTokenResponse.class);

        return KeycloakSpringAdapterUtils.createKeycloakSecurityContext(keycloakDeployment, response);
    }

    @Override
    public void logout(String refreshToken) {

        ArrayList<KeyValuePair> bodyParams = bodyParamsForRefreshToken(refreshToken);
        template.exchange(keycloakDeployment.getLogoutUrl().build(),
                HttpMethod.POST, new HttpEntity<>(createBody(bodyParams), createHeaders()), String.class);
    }

    @Override
    public RefreshableKeycloakSecurityContext refresh(String refreshToken) throws VerificationException {
        ArrayList<KeyValuePair> bodyParams = bodyParamsForRefreshToken(refreshToken);
        bodyParams.add(new KeyValuePair(OAuth2Constants.GRANT_TYPE, OAuth2Constants.REFRESH_TOKEN));

        AccessTokenResponse response = template.postForObject(keycloakDeployment.getTokenUrl(), new HttpEntity<>(createBody(bodyParams),
                createHeaders()), AccessTokenResponse.class);

        return KeycloakSpringAdapterUtils.createKeycloakSecurityContext(keycloakDeployment, response);
    }

    private ArrayList<KeyValuePair> bodyParamsForRefreshToken(String refreshToken) {
        ArrayList<KeyValuePair> bodyParams = new ArrayList<>();

        bodyParams.add(new KeyValuePair("client_id", keycloakDeployment.getResourceName()));
        bodyParams.add(new KeyValuePair("client_secret", keycloakDeployment.getResourceCredentials().get("secret").toString()));
        bodyParams.add(new KeyValuePair("refresh_token", refreshToken));

        return bodyParams;
    }

    private MultiValueMap<String, String> createBody(ArrayList<KeyValuePair> valuePairList) {
        final LinkedMultiValueMap body = new LinkedMultiValueMap<>();

        for (KeyValuePair valuePair : valuePairList) {
            body.add(valuePair.key, valuePair.value);
        }

        return body;
    }

    private HttpHeaders createHeaders() {
        final HttpHeaders headers = new HttpHeaders();

        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));

        return headers;
    }

    class KeyValuePair {

        private String key;
        private String value;

        public KeyValuePair(String key, String value) {
            this.key = key;
            this.value = value;
        }
    }
}
