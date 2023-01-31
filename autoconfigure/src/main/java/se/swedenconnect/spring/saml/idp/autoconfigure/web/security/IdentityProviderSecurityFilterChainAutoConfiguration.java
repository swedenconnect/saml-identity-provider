/*
 * Copyright 2022-2023 Sweden Connect
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package se.swedenconnect.spring.saml.idp.autoconfigure.web.security;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import se.swedenconnect.spring.saml.idp.config.annotation.web.configuration.Saml2IdpConfiguration;

/**
 * Auto configuration class for setting up the {@link SecurityFilterChain} for the SAML IdP.
 * 
 * @author Martin Lindström
 */
@AutoConfiguration
public class IdentityProviderSecurityFilterChainAutoConfiguration {
  
  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  SecurityFilterChain samlIdpSecurityFilterChain(final HttpSecurity http)
      throws Exception {

    // Apply the default configuration for the IdP.
    //
    Saml2IdpConfiguration.applyDefaultSecurity(http);

//    http
//        .anonymous().disable()
//        .rememberMe().disable()
//        .exceptionHandling((exceptions) -> exceptions
//            .authenticationEntryPoint(new RedirectToClientAuthenticationEntryPoint()));

    http.exceptionHandling((exceptions) -> exceptions
        .authenticationEntryPoint(
            new LoginUrlAuthenticationEntryPoint("/login")));

    return http.build();
  }

}
