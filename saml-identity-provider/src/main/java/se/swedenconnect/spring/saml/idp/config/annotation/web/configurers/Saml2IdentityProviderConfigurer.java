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
package se.swedenconnect.spring.saml.idp.config.annotation.web.configurers;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;

import se.swedenconnect.spring.saml.idp.settings.CredentialSettings;
import se.swedenconnect.spring.saml.idp.settings.IdentityProviderSettings;

/**
 * An {@link AbstractHttpConfigurer} for SAML2 Identity Provider support.
 *
 * @author Martin Lindström
 */
public class Saml2IdentityProviderConfigurer
    extends AbstractHttpConfigurer<Saml2IdentityProviderConfigurer, HttpSecurity> {

  /** The configurers for the SAML2 Identity Provider. */
  private final Map<Class<? extends AbstractSaml2Configurer>, AbstractSaml2Configurer> configurers =
      this.createConfigurers();

  /** The endpoints matcher. */
  private RequestMatcher endpointsMatcher;

  /**
   * Configures the IdP metadata endpoint.
   *
   * @param customizer the {@link Customizer} providing access to the {@link IdentityProviderMetadataEndpointConfigurer}
   * @return the {@link Saml2IdentityProviderConfigurer} for further configuration
   */
  public Saml2IdentityProviderConfigurer idpMetadataEndpoint(
      final Customizer<IdentityProviderMetadataEndpointConfigurer> customizer) {
    customizer.customize(this.getConfigurer(IdentityProviderMetadataEndpointConfigurer.class));
    return this;
  }

  /**
   * Returns a {@link RequestMatcher} for the SAML Identity Provider endpoints.
   *
   * @return a {@link RequestMatcher} for the SAML Identity Provider endpoints
   */
  public RequestMatcher getEndpointsMatcher() {
    // Use a deferred RequestMatcher since endpointsMatcher is constructed in init(HttpSecurity).
    //
    return (request) -> this.endpointsMatcher.matches(request);
  }

  /** {@inheritDoc} */
  @Override
  public void init(final HttpSecurity httpSecurity) {
    final IdentityProviderSettings identityProviderSettings =
        Saml2ConfigurerUtils.getIdentityProviderSettings(httpSecurity);
    validateIdentityProviderSettings(identityProviderSettings);

    final List<RequestMatcher> requestMatchers = new ArrayList<>();
    this.configurers.values().forEach(configurer -> {
      configurer.init(httpSecurity);
      requestMatchers.add(configurer.getRequestMatcher());
    });
//    requestMatchers.add(new AntPathRequestMatcher(
//        authorizationServerSettings.getJwkSetEndpoint(), HttpMethod.GET.name()));
    this.endpointsMatcher = new OrRequestMatcher(requestMatchers);

    // TODO: Change
//    ExceptionHandlingConfigurer<HttpSecurity> exceptionHandling =
//        httpSecurity.getConfigurer(ExceptionHandlingConfigurer.class);
//    if (exceptionHandling != null) {
//      exceptionHandling.defaultAuthenticationEntryPointFor(
//          new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
//          new OrRequestMatcher(
//              getRequestMatcher(OAuth2TokenEndpointConfigurer.class),
//              getRequestMatcher(OAuth2TokenIntrospectionEndpointConfigurer.class),
//              getRequestMatcher(OAuth2TokenRevocationEndpointConfigurer.class)));
//    }
  }

  /** {@inheritDoc} */
  @Override
  public void configure(final HttpSecurity httpSecurity) {
    this.configurers.values().forEach(configurer -> configurer.configure(httpSecurity));

    final IdentityProviderSettings identityProviderSettings =
        Saml2ConfigurerUtils.getIdentityProviderSettings(httpSecurity);

    // Add context filter ...
    //
    final IdentityProviderContextFilter contextFilter = new IdentityProviderContextFilter(identityProviderSettings);
    httpSecurity.addFilterAfter(this.postProcess(contextFilter), SecurityContextHolderFilter.class);


    // TODO
  }

  /**
   * Creates the configurers for the SAML2 Identity Provider.
   *
   * @return a map of configurers
   */
  private Map<Class<? extends AbstractSaml2Configurer>, AbstractSaml2Configurer> createConfigurers() {
    final Map<Class<? extends AbstractSaml2Configurer>, AbstractSaml2Configurer> configurers = new LinkedHashMap<>();
    configurers.put(IdentityProviderMetadataEndpointConfigurer.class,
        new IdentityProviderMetadataEndpointConfigurer(this::postProcess));
//    configurers.put(OAuth2ClientAuthenticationConfigurer.class, new OAuth2ClientAuthenticationConfigurer(this::postProcess));
//    configurers.put(OAuth2AuthorizationServerMetadataEndpointConfigurer.class, new OAuth2AuthorizationServerMetadataEndpointConfigurer(this::postProcess));
//    configurers.put(OAuth2AuthorizationEndpointConfigurer.class, new OAuth2AuthorizationEndpointConfigurer(this::postProcess));
//    configurers.put(OAuth2TokenEndpointConfigurer.class, new OAuth2TokenEndpointConfigurer(this::postProcess));
//    configurers.put(OAuth2TokenIntrospectionEndpointConfigurer.class, new OAuth2TokenIntrospectionEndpointConfigurer(this::postProcess));
//    configurers.put(OAuth2TokenRevocationEndpointConfigurer.class, new OAuth2TokenRevocationEndpointConfigurer(this::postProcess));
    return configurers;
  }

  @SuppressWarnings("unchecked")
  private <T> T getConfigurer(final Class<T> type) {
    return (T) this.configurers.get(type);
  }

  private <T extends AbstractSaml2Configurer> void addConfigurer(final Class<T> configurerType, final T configurer) {
    this.configurers.put(configurerType, configurer);
  }

  private <T extends AbstractSaml2Configurer> RequestMatcher getRequestMatcher(final Class<T> configurerType) {
    final T configurer = this.getConfigurer(configurerType);
    return configurer != null ? configurer.getRequestMatcher() : null;
  }

  /**
   * Validates that {@link IdentityProviderSettings} has been set up so that the Identity Provider can function.
   *
   * @param identityProviderSettings the settings to validate
   */
  public static void validateIdentityProviderSettings(final IdentityProviderSettings identityProviderSettings)
      throws IllegalArgumentException {
    if (!StringUtils.hasText(identityProviderSettings.getEntityId())) {
      throw new IllegalArgumentException("Identity Provider entityID must be assigned");
    }
    if (identityProviderSettings.getBaseUrl().endsWith("/")) {
      throw new IllegalArgumentException("Base URL must not end with /");
    }
    if (identityProviderSettings.getHokBaseUrl() != null
        && identityProviderSettings.getHokBaseUrl().endsWith("/")) {
      throw new IllegalArgumentException("HoK base URL must not end with /");
    }

    // Assert credentials
    //
    final CredentialSettings credentials = identityProviderSettings.getCredentials();
    if (credentials == null) {
      throw new IllegalArgumentException("No Identity Provider credentials have been assigned");
    }
    final boolean defaultCredentialAssigned = credentials.getDefaultCredential() != null;
    if (credentials.getSignCredential() == null && !defaultCredentialAssigned) {
      throw new IllegalArgumentException("No signing credential has been assigned (and no default)");
    }
    if (credentials.getEncryptCredential() == null && !defaultCredentialAssigned) {
      throw new IllegalArgumentException("No signing credential has been assigned (and no default)");
    }

    // Assert endpoints
    //
    if (!identityProviderSettings.getEndpoints().getMetadataEndpoint().startsWith("/")) {
      throw new IllegalArgumentException("Invalid endpoint - metadata path must begin with /");
    }
  }

}
