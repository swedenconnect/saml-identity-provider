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
package se.swedenconnect.spring.saml.idp.config.annotation.web.configurers;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import javax.servlet.http.HttpServletRequest;

import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationConverter;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationProvider;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;
import se.swedenconnect.spring.saml.idp.settings.IdentityProviderSettings;
import se.swedenconnect.spring.saml.idp.web.filters.Saml2AuthnRequestProcessingFilter;
import se.swedenconnect.spring.saml.idp.web.filters.Saml2ErrorResponseProcessingFilter;

/**
 * A configurer for the processing of SAML2 {@code AuthnRequest} messages.
 */
public class Saml2AuthnRequestProcessorConfigurer extends AbstractSaml2Configurer {

  /** The request matcher. */
  private RequestMatcher requestMatcher;

  /** The configurer for creating a {@link Saml2AuthnRequestAuthenticationProvider}. */
  private Saml2AuthnRequestAuthenticationProviderConfigurer authenticationProviderConfigurer =
      new Saml2AuthnRequestAuthenticationProviderConfigurer();

  /** May be used to override the use of {@link Saml2AuthnRequestAuthenticationProvider}. */
  private AuthenticationProvider customAuthenticationProvider;

  /** The converter(s) handling {@code AuthnRequest} messages. */
  private final List<AuthenticationConverter> authnRequestConverters = new ArrayList<>();

  /** A consumer for modifying the {@code authnRequestConverters}. */
  private Consumer<List<AuthenticationConverter>> authnRequestConvertersConsumer = (converters) -> {
  };

  /**
   * An {@link AuthenticationSuccessHandler} for customized handling of successful authentication of relying parties.
   */
  private AuthenticationSuccessHandler authenticationSuccessHandler;

  /**
   * Constructor.
   * 
   * @param objectPostProcessor the object post processor
   */
  Saml2AuthnRequestProcessorConfigurer(final ObjectPostProcessor<Object> objectPostProcessor) {
    super(objectPostProcessor);
  }

  /**
   * Adds an {@link AuthenticationConverter} used when attempting to extract an {@code AuthnRequest} from
   * {@link HttpServletRequest} to an instance of {@link Saml2AuthnRequestAuthenticationToken} used for authenticating
   * the request and to process it further.
   *
   * @param authnRequestConverter an {@link AuthenticationConverter} used when attempting to extract an
   *          {@code AuthnRequest} from {@link HttpServletRequest}
   * @return the {@link Saml2AuthnRequestProcessorConfigurer} for further configuration
   */
  public Saml2AuthnRequestProcessorConfigurer authnRequestConverter(
      final AuthenticationConverter authnRequestConverter) {
    Assert.notNull(authnRequestConverter, "authnRequestConverter cannot be null");
    this.authnRequestConverters.add(authnRequestConverter);
    return this;
  }

  /**
   * Sets the {@code Consumer} providing access to the {@code List} of default and (optionally) added
   * {@link #authnRequestConverter(AuthenticationConverter) AuthenticationConverter}'s allowing the ability to add,
   * remove, or customize a specific {@link AuthenticationConverter}.
   *
   * @param authnRequestConvertersConsumer the {@code Consumer} providing access to the {@code List} of default and
   *          (optionally) added {@link AuthenticationConverter}'s
   * @return the {@link Saml2AuthnRequestProcessorConfigurer} for further configuration
   */
  public Saml2AuthnRequestProcessorConfigurer authnRequestConverters(
      Consumer<List<AuthenticationConverter>> authnRequestConvertersConsumer) {
    Assert.notNull(authnRequestConvertersConsumer, "authnRequestConvertersConsumer cannot be null");
    this.authnRequestConvertersConsumer = authnRequestConvertersConsumer;
    return this;
  }

  /**
   * Customizes the {@link Saml2AuthnRequestAuthenticationProviderConfigurer} that is used to create the default
   * authentication provider - {@link Saml2AuthnRequestAuthenticationProvider}.
   * 
   * @param customizer the customizer that is given access to the
   *          {@link Saml2AuthnRequestAuthenticationProviderConfigurer}
   * @return the {@link Saml2AuthnRequestProcessorConfigurer} for further configuration
   */
  public Saml2AuthnRequestProcessorConfigurer authenticationProvider(
      final Customizer<Saml2AuthnRequestAuthenticationProviderConfigurer> customizer) {
    customizer.customize(this.authenticationProviderConfigurer);
    return this;
  }

  /**
   * Installs a custom {@link AuthenticationProvider} to be used instead of
   * {@link Saml2AuthnRequestAuthenticationProvider}.
   * <p>
   * </p>
   *
   * @param customAuthenticationProvider an {@link AuthenticationProvider} used for authenticating an
   *          {@link Saml2AuthnRequestAuthenticationToken}
   * @return the {@link Saml2AuthnRequestProcessorConfigurer} for further configuration
   */
  public Saml2AuthnRequestProcessorConfigurer customAuthenticationProvider(
      final AuthenticationProvider customAuthenticationProvider) {
    this.customAuthenticationProvider = customAuthenticationProvider;
    return this;
  }

  /**
   * Sets the {@link AuthenticationSuccessHandler} used for handling a successful SP (relying party) authentication and
   * associating the {@link Saml2AuthnRequestAuthenticationToken} to the {@link SecurityContext}.
   *
   * @param authenticationSuccessHandler the {@link AuthenticationSuccessHandler} used for handling a successful SP
   *          authentication
   * @return the {@link Saml2AuthnRequestProcessorConfigurer} for further configuration
   */
  public Saml2AuthnRequestProcessorConfigurer authenticationSuccessHandler(
      final AuthenticationSuccessHandler authenticationSuccessHandler) {
    this.authenticationSuccessHandler = authenticationSuccessHandler;
    return this;
  }

  /** {@inheritDoc} */
  @Override
  protected void init(final HttpSecurity httpSecurity) {
    this.requestMatcher = Saml2IdpConfigurerUtils.getAuthnEndpointsRequestMatcher(httpSecurity);
 
    this.authenticationProviderConfigurer.init(httpSecurity);
  }

  /** {@inheritDoc} */
  @Override
  void configure(final HttpSecurity httpSecurity) {
    
    final AuthenticationProvider authenticationProvider = this.customAuthenticationProvider != null
        ? this.customAuthenticationProvider
        : this.authenticationProviderConfigurer.getObject(httpSecurity);
    
    httpSecurity.authenticationProvider(this.postProcess(authenticationProvider));

    final List<AuthenticationConverter> authnConverters = new ArrayList<>();
    final IdentityProviderSettings settings = Saml2IdpConfigurerUtils.getIdentityProviderSettings(httpSecurity);
    final MetadataResolver resolver = httpSecurity.getSharedObject(MetadataResolver.class);
    authnConverters.add(new Saml2AuthnRequestAuthenticationConverter(resolver, settings));
    
    if (!this.authnRequestConverters.isEmpty()) {
      authnConverters.addAll(0, this.authnRequestConverters);
    }
    this.authnRequestConvertersConsumer.accept(authnConverters);
    final AuthenticationConverter authnRequestConverter = authnConverters.size() == 1
        ? authnConverters.get(0)
        : (r) -> {
          for (final AuthenticationConverter c : authnConverters) {
            final Authentication a = c.convert(r);
            if (a != null) {
              return a;
            }
          }
          return null;
        };

    final AuthenticationManager authenticationManager = httpSecurity.getSharedObject(AuthenticationManager.class);

    final Saml2AuthnRequestProcessingFilter filter =
        new Saml2AuthnRequestProcessingFilter(authenticationManager, this.requestMatcher, authnRequestConverter);
    if (this.authenticationSuccessHandler != null) {
      filter.setAuthenticationSuccessHandler(this.authenticationSuccessHandler);
    }

    httpSecurity.addFilterAfter(this.postProcess(filter), Saml2ErrorResponseProcessingFilter.class);
  }
  
  /** {@inheritDoc} */
  @Override
  RequestMatcher getRequestMatcher() {
    return null;
  }

}
