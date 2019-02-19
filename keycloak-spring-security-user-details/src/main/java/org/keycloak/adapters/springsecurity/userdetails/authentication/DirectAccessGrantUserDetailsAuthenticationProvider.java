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

package org.keycloak.adapters.springsecurity.userdetails.authentication;

import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.OidcKeycloakAccount;
import org.keycloak.adapters.springsecurity.authentication.DirectAccessGrantAuthenticationProvider;
import org.keycloak.adapters.springsecurity.service.DirectAccessGrantService;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.adapters.springsecurity.userdetails.token.KeycloakUserDetailsAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.util.Assert;

import java.security.Principal;

/**
 * Provides a {@link DirectAccessGrantAuthenticationProvider} capable of
 * swapping the Keycloak principal with a {@link UserDetails user details} principal.
 *
 * <p>
 *     The supplied {@link UserDetailsService} is consulted using the Keycloak
 *     access token's principal attribute as the username.
 * </p>
 *
 * The original Keycloak principal is available from the {@link KeycloakAuthenticationToken}:
 *     <pre>
 *          KeycloakAuthenticationToken token = (KeycloakAuthenticationToken) SecurityContextHolder.getContext().getAuthentication());
 *          KeycloakAccount account = token.getAccount();
 *          Principal = account.getPrincipal();
 *     </pre>
 *
 * @author <a href="mailto:srossillo@smartling.com">Scott Rossillo</a>
 *
 * @see UserDetailsService#loadUserByUsername
 * @see KeycloakUserDetailsAuthenticationToken
 */
public class DirectAccessGrantUserDetailsAuthenticationProvider extends DirectAccessGrantAuthenticationProvider
{

    protected final UserDetailsService userDetailsService;

    public DirectAccessGrantUserDetailsAuthenticationProvider(KeycloakDeployment keycloakDeployment, DirectAccessGrantService directAccessGrantService,
                                                              UserDetailsService userDetailsService) {
        super(keycloakDeployment, directAccessGrantService);
        this.userDetailsService = userDetailsService;
    }


    /**
     * Returns the username from the given {@link KeycloakAuthenticationToken}. By default, this method
     * resolves the username from the token's {@link KeycloakPrincipal}'s name. This value can be controlled
     * via <code>keycloak.json</code>'s
     * <a href="http://docs.jboss.org/keycloak/docs/1.2.0.CR1/userguide/html/ch08.html#adapter-config"><code>principal-attribute</code></a>.
     * For more fine-grained username resolution, override this method.
     *
     * @param token the {@link KeycloakAuthenticationToken} from which to extract the username
     *
     * @return the username to use when loading a user from the this provider's {@link UserDetailsService}.
     *
     * @see UserDetailsService#loadUserByUsername
     * @see OidcKeycloakAccount#getPrincipal
     */
    protected String resolveUsername(KeycloakAuthenticationToken token) {

        Assert.notNull(token, "KeycloakAuthenticationToken required");
        Assert.notNull(token.getAccount(), "KeycloakAuthenticationToken.getAccount() cannot be return null");
        OidcKeycloakAccount account = token.getAccount();
        Principal principal = account.getPrincipal();

        return principal.getName();
    }
}
