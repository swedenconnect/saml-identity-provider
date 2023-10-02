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
import org.springframework.boot.actuate.audit.InMemoryAuditEventRepository;
import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.thymeleaf.spring6.SpringTemplateEngine;

import se.swedenconnect.spring.saml.idp.attributes.nameid.DefaultNameIDGeneratorFactory;
import se.swedenconnect.spring.saml.idp.config.configurers.Saml2IdpConfigurerAdapter;
import se.swedenconnect.spring.saml.idp.demo.authn.SimulatedAuthenticationController;
import se.swedenconnect.spring.saml.idp.demo.authn.SimulatedAuthenticationProvider;
import se.swedenconnect.spring.saml.idp.demo.user.SimulatedUserDetailsManager;
import se.swedenconnect.spring.saml.idp.demo.user.UsersConfigurationProperties;
import se.swedenconnect.spring.saml.idp.response.ThymeleafResponsePage;
import se.swedenconnect.spring.saml.idp.settings.IdentityProviderSettings;

/**
 * Configuration for the IdP.
 *
 * @author Martin Lindström
 */
@Configuration
@EnableConfigurationProperties
public class IdpConfiguration {

  /**
   * The {@link IdentityProviderSettings}. Created by the Spring Boot autoconfiguration from reading the application
   * properties file.
   */
  @Autowired
  IdentityProviderSettings settings;

  /**
   * The simulated users.
   */
  @Autowired
  UsersConfigurationProperties userProps;

  /**
   * Our simulated users.
   *
   * @return an {@link UserDetailsService}
   */
  @Bean
  UserDetailsService userDetailsService() {
    final SimulatedUserDetailsManager mgr = new SimulatedUserDetailsManager();
    this.userProps.getUsers().stream().forEach(u -> mgr.createUser(u));
    return mgr;
  }

  /**
   * Creates the authentication provider bean.
   *
   * @return a {@link SimulatedAuthenticationProvider}
   */
  @Bean
  SimulatedAuthenticationProvider simulatedAuthenticationProvider() {
    return new SimulatedAuthenticationProvider(SimulatedAuthenticationController.AUTHN_PATH, "/simulated1");
  }

  /**
   * Gets a {@link Saml2IdpConfigurerAdapter} that configures the IdP past configuration using application properties.
   *
   * @param templateEngine the template engine (needed for setting up our own POST page)
   * @return a {@link Saml2IdpConfigurerAdapter}
   */
  @Bean
  Saml2IdpConfigurerAdapter samlIdpConfigurer(final SpringTemplateEngine templateEngine) {
    return (h, c) -> {
      // Override the HTML page that is used to post back the SAML response with our own ...
      c.responseSender((s) -> s.setResponsePage(new ThymeleafResponsePage(templateEngine, "post-response.html")));

      // Example of how we change the NameID default from persistent to transient
      c.authnRequestProcessor(p -> p.authenticationProvider(
          a -> {
            DefaultNameIDGeneratorFactory f = new DefaultNameIDGeneratorFactory(this.settings.getEntityId());
            f.setDefaultFormat(NameID.TRANSIENT);
            a.nameIDGeneratorFactory(f);
          }));
    };
  }

  @Bean
  @Order(2)
  SecurityFilterChain defaultSecurityFilterChain(final HttpSecurity http) throws Exception {
    http
        .csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
        .cors(Customizer.withDefaults())
        .authorizeHttpRequests((authorize) -> authorize
            .requestMatchers("/images/**", "/error", "/assets/**", "/scripts/**", "/webjars/**", "/view/**", "/api/**",
                "/css/**", "/resume/**", SimulatedAuthenticationController.AUTHN_PATH + "/**")
            .permitAll()
            .requestMatchers(EndpointRequest.toAnyEndpoint()).permitAll()
            .anyRequest().denyAll());

    return http.build();
  }

  @Bean
  InMemoryAuditEventRepository repository() {
    return new InMemoryAuditEventRepository();
  }

}
