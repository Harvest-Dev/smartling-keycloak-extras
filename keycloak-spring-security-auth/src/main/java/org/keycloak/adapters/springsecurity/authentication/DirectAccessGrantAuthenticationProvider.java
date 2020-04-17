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
package org.keycloak.adapters.springsecurity.authentication;

import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.RefreshableKeycloakSecurityContext;
import org.keycloak.adapters.springsecurity.service.DirectAccessGrantService;
import org.keycloak.adapters.springsecurity.support.KeycloakSpringAdapterUtils;
import org.keycloak.adapters.springsecurity.token.DirectAccessGrantToken;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.common.VerificationException;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import org.keycloak.adapters.KeycloakConfigResolver;

/**
 * {@link AuthenticationProvider} implementing the OAuth2 resource owner password credentials
 * grant for clients secured by Keycloak.
 *
 * <p>
 * The resource owner password credentials grant type is suitable in
 * cases where the resource owner has a trust relationship with the
 * client, such as the device operating system or a highly privileged
 * application.
 * </p>
 *
 * @author <a href="mailto:srossillo@smartling.com">Scott Rossillo</a>
 */
public class DirectAccessGrantAuthenticationProvider implements AuthenticationProvider
{

    protected final KeycloakConfigResolver configResolver;

    protected KeycloakDeployment keycloakDeployment;

    protected final DirectAccessGrantService directAccessGrantService;

    private GrantedAuthoritiesMapper grantedAuthoritiesMapper = null;

    public DirectAccessGrantAuthenticationProvider(KeycloakConfigResolver configResolver, DirectAccessGrantService directAccessGrantService)
    {
        this.configResolver = configResolver;
        this.directAccessGrantService = directAccessGrantService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException
    {
        String username = resolveUsername(authentication.getPrincipal());
        String password = (String) authentication.getCredentials();
        RefreshableKeycloakSecurityContext context;
        KeycloakAuthenticationToken token;
        Collection<? extends GrantedAuthority> authorities;

        try
        {
            resolveKeycloakDeploymentIfNull();
            context = directAccessGrantService.login(username, password);
            authorities = KeycloakSpringAdapterUtils.createGrantedAuthorities(context, grantedAuthoritiesMapper);
            token = new KeycloakAuthenticationToken(KeycloakSpringAdapterUtils.createAccount(keycloakDeployment, context), true, authorities);
        }
        catch(VerificationException e)
        {
            throw new BadCredentialsException("Unable to validate token", e);
        }
        catch(Exception e)
        {
            throw new AuthenticationServiceException("Error authenticating with Keycloak server", e);
        }

        return token;
    }

    /**
     * Returns the username for the given principal.
     *
     * @param principal the principal to authenticate
     * @return the username from the given <code>principal</code>
     * @throws AuthenticationCredentialsNotFoundException if the username cannot be resolved
     */
    public String resolveUsername(Object principal)
    {

        if(principal instanceof String)
        {
            return (String) principal;
        }

        if(principal instanceof UserDetails)
        {
            return ((UserDetails) principal).getUsername();
        }

        throw new AuthenticationCredentialsNotFoundException("Can't find username on: " + principal);
    }

    @Override
    public boolean supports(Class<?> authentication)
    {
        return DirectAccessGrantToken.class.isAssignableFrom(authentication)
            || UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

    /**
     * Set the optional {@link GrantedAuthoritiesMapper} for this {@link AuthenticationProvider}.
     *
     * @param grantedAuthoritiesMapper the <code>GrantedAuthoritiesMapper</code> to use
     */
    public void setGrantedAuthoritiesMapper(GrantedAuthoritiesMapper grantedAuthoritiesMapper)
    {
        this.grantedAuthoritiesMapper = grantedAuthoritiesMapper;
    }

    /**
     *
     * @param refreshToken
     */
    public void logout(String refreshToken)
    {
        this.directAccessGrantService.logout(refreshToken);
    }

    /**
     * Get new token for the provided refresh_token
     * @param refreshToken
     * @return
     */
    public Authentication refresh(String refreshToken)
    {
        RefreshableKeycloakSecurityContext context;
        KeycloakAuthenticationToken token;
        Collection<? extends GrantedAuthority> authorities;

        try
        {
            resolveKeycloakDeploymentIfNull();
            context = directAccessGrantService.refresh(refreshToken);
            authorities = KeycloakSpringAdapterUtils.createGrantedAuthorities(context, grantedAuthoritiesMapper);
            token = new KeycloakAuthenticationToken(KeycloakSpringAdapterUtils.createAccount(keycloakDeployment, context), true, authorities);
        }
        catch(VerificationException e)
        {
            throw new BadCredentialsException("Unable to validate token", e);
        }
        catch(Exception e)
        {
            throw new AuthenticationServiceException("Error authenticating with Keycloak server", e);
        }

        return token;
    }

    /**
     * Permet la résolution du keycloakDeployment si celui-ci est null
     */
    private void resolveKeycloakDeploymentIfNull()
    {
        if(keycloakDeployment == null)
        {
            keycloakDeployment = configResolver.resolve(null);
        }
    }
}
