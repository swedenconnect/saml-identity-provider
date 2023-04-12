/*
 * Copyright 2023 Sweden Connect
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
package se.swedenconnect.spring.saml.idp.demo;

import org.opensaml.saml.saml2.core.NameID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;

import se.swedenconnect.spring.saml.idp.attributes.nameid.DefaultNameIDGeneratorFactory;
import se.swedenconnect.spring.saml.idp.config.configurers.Saml2IdpConfigurerAdapter;
import se.swedenconnect.spring.saml.idp.demo.authn.SimulatedAuthenticationController;
import se.swedenconnect.spring.saml.idp.demo.authn.SimulatedAuthenticationProvider;
import se.swedenconnect.spring.saml.idp.settings.IdentityProviderSettings;

@Configuration
@EnableConfigurationProperties
public class IdpConfiguration {

  @Autowired
  IdentityProviderSettings settings;

  @Autowired
  UsersConfigurationProperties userProps;

  // TODO: make sure a default is present
//  @Bean
//  ExternalAuthenticatorTokenRepository externalAuthenticationRepository() {
//    return new SessionBasedExternalAuthenticationRepository();
//  }

  @Bean
  UserDetailsService userDetailsService() {
    final SimulatedUserDetailsManager mgr = new SimulatedUserDetailsManager();
    this.userProps.getUsers().stream().forEach(u -> mgr.createUser(u));
    return mgr;
  }

  @Bean
  SimulatedAuthenticationProvider simulatedAuthenticationProvider() {
    return new SimulatedAuthenticationProvider(SimulatedAuthenticationController.AUTHN_PATH, "/simulated1");
  }

  @Bean
  Saml2IdpConfigurerAdapter nameIdConfigurer() {
    return (h, c) -> {
      c.authnRequestProcessor(p -> p.authenticationProvider(
          a -> {
            DefaultNameIDGeneratorFactory f = new DefaultNameIDGeneratorFactory(this.settings.getEntityId());
            f.setDefaultFormat(NameID.TRANSIENT);
            a.nameIDGeneratorFactory(f);
          }));
    };
  }

  // HttpSecurityConfiguration c;

//  @Order(Ordered.HIGHEST_PRECEDENCE)
//  @Bean
//  SecurityFilterChain samlIdpSecurityFilterChain2(final HttpSecurity http) throws Exception {
//
////    if (this.providers != null) {
////      this.providers.forEach(p -> http.authenticationProvider(p));
////    }
//
//    Saml2IdpConfiguration.applyDefaultSecurity(http, List.of(this.simulatedAuthenticationProvider()));
//
//    // SecurityContextPersistenceFilter f;
//    // SecurityContextHolderFilter f2;
//
//    SecurityFilterChain c = http.build();
//
//    return c;
//    // return http.build();
//  }

}
