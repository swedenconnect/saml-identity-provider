/*
 * Copyright 2022 Sweden Connect
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
package se.swedenconnect.spring.saml.idp.config;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.spring.saml.idp.audit.Saml2IdpAuditListener;
import se.swedenconnect.spring.saml.idp.authentication.provider.UserAuthenticationProvider;
import se.swedenconnect.spring.saml.idp.authentication.provider.external.UserRedirectAuthenticationProvider;
import se.swedenconnect.spring.saml.idp.config.configurers.Saml2IdpConfigurer;
import se.swedenconnect.spring.saml.idp.config.configurers.Saml2IdpConfigurerAdapter;
import se.swedenconnect.spring.saml.idp.response.ResponsePage;
import se.swedenconnect.spring.saml.idp.settings.IdentityProviderSettings;

/**
 * {@link Configuration} for SAML Identity Provider support.
 *
 * @author Martin Lindström
 */
@Configuration(proxyBeanMethods = false)
@Slf4j
public class Saml2IdpConfiguration {

  /**
   * Creates a {@link SecurityFilterChain} for the SAML Identity Provider.
   *
   * @param http the HttpSecurity object
   * @param authenticationProviders a list of authentication providers
   * @param adapters the configuration adapters
   * @param responsePage a custom response page (may be {@code null})
   * @return a SecurityFilterChain
   * @throws Exception for configuration errors
   */
  @Bean("samlIdpSecurityFilterChain")
  @Order(Ordered.HIGHEST_PRECEDENCE)
  SecurityFilterChain identityProviderSecurityFilterChain(final HttpSecurity http,
      @Autowired(required = false) final List<UserAuthenticationProvider> authenticationProviders,
      @Autowired(required = false) final List<Saml2IdpConfigurerAdapter> adapters,
      @Autowired(required = false) final ResponsePage responsePage) throws Exception {
    applyDefaultSecurity(http, authenticationProviders);

    if (responsePage != null) {
      http.getConfigurer(Saml2IdpConfigurer.class)
          .responseSender(s -> s.setResponsePage(responsePage));
    }

    if (adapters != null && !adapters.isEmpty()) {
      final Saml2IdpConfigurer idpConfigurer = http.getConfigurer(Saml2IdpConfigurer.class);
      for (final Saml2IdpConfigurerAdapter adapter : adapters) {
        adapter.configure(http, idpConfigurer);
      }
    }

    return http.build();
  }

  /**
   * Applies the default security settings for the SAML Identity Provider.
   *
   * @param http the HttpSecurity object
   * @throws Exception for configuration errors
   */
  public static void applyDefaultSecurity(final HttpSecurity http,
      final List<UserAuthenticationProvider> authenticationProviders) throws Exception {

    final Saml2IdpConfigurer idpConfigurer = new Saml2IdpConfigurer();

    if (authenticationProviders != null && !authenticationProviders.isEmpty()) {

      for (final UserAuthenticationProvider provider : authenticationProviders) {
        log.debug("Adding '{}' ({}) bean as authentication provider", provider.getName(),
            provider.getClass().getSimpleName());
        http.authenticationProvider(provider);

        if (provider instanceof UserRedirectAuthenticationProvider) {
          idpConfigurer.userAuthentication((c) -> c.resumeAuthnPath(
              ((UserRedirectAuthenticationProvider) provider).getResumeAuthnPath()));
        }
      }

    }

    final RequestMatcher endpointsMatcher = idpConfigurer.getEndpointsMatcher();

    http
        .requestMatcher(endpointsMatcher)
        .authorizeHttpRequests(authorizeRequests -> authorizeRequests.anyRequest().authenticated())
        .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
        .apply(idpConfigurer);
  }

  /**
   * Creates the {@link Saml2IdpAuditListener}.
   * 
   * @param publisher the event publisher
   * @return a {@link Saml2IdpAuditListener}
   */
  @Bean
  Saml2IdpAuditListener saml2IdpAuditListener(final ApplicationEventPublisher publisher) {
    return new Saml2IdpAuditListener(publisher);
  }

  @Bean
  RegisterMissingBeanPostProcessor registerMissingBeanPostProcessor() {
    final RegisterMissingBeanPostProcessor postProcessor = new RegisterMissingBeanPostProcessor();
    postProcessor.addBeanDefinition(IdentityProviderSettings.class, () -> IdentityProviderSettings.builder().build());
    return postProcessor;
  }

}
