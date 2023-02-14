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
import org.opensaml.xmlsec.signature.support.SignatureTrustEngine;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import se.swedenconnect.opensaml.saml2.response.replay.MessageReplayChecker;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationConverter;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationProvider;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;
import se.swedenconnect.spring.saml.idp.authnrequest.validation.AuthnRequestSignatureValidator;
import se.swedenconnect.spring.saml.idp.authnrequest.validation.AuthnRequestValidator;
import se.swedenconnect.spring.saml.idp.settings.IdentityProviderSettings;
import se.swedenconnect.spring.saml.idp.web.filters.Saml2AuthnRequestProcessingFilter;

/**
 * A configurer for the processing of SAML2 {@code AuthnRequest} messages.
 */
public class Saml2AuthnRequestProcessorConfigurer extends AbstractSaml2Configurer {

  /** The request matcher. */
  private RequestMatcher requestMatcher;

  /** The converter(s) handling {@code AuthnRequest} messages. */
  private final List<AuthenticationConverter> authnRequestConverters = new ArrayList<>();

  /** A consumer for modifying the {@code authnRequestConverters}. */
  private Consumer<List<AuthenticationConverter>> authnRequestConvertersConsumer = (converters) -> {
  };

  /** The authentication provider(s) handling {@code AuthnRequest} messages. */
  private final List<AuthenticationProvider> authenticationProviders = new ArrayList<>();

  /** A consumer for modifying the {@code authenticationProviders}. */
  private Consumer<List<AuthenticationProvider>> authenticationProvidersConsumer = (authenticationProviders) -> {
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
   * Adds an {@link AuthenticationProvider} used for authenticating an {@link Saml2AuthnRequestAuthenticationToken}.
   *
   * @param authenticationProvider an {@link AuthenticationProvider} used for authenticating an
   *          {@link Saml2AuthnRequestAuthenticationToken}
   * @return the {@link Saml2AuthnRequestProcessorConfigurer} for further configuration
   */
  public Saml2AuthnRequestProcessorConfigurer authenticationProvider(
      final AuthenticationProvider authenticationProvider) {
    Assert.notNull(authenticationProvider, "authenticationProvider cannot be null");
    this.authenticationProviders.add(authenticationProvider);
    return this;
  }

  /**
   * Sets the {@code Consumer} providing access to the {@code List} of default and (optionally) added
   * {@link #authenticationProvider(AuthenticationProvider) AuthenticationProvider}'s allowing the ability to add,
   * remove, or customize a specific {@link AuthenticationProvider}.
   *
   * @param authenticationProvidersConsumer the {@code Consumer} providing access to the {@code List} of default and
   *          (optionally) added {@link AuthenticationProvider}'s
   * @return the {@link Saml2AuthnRequestProcessorConfigurer} for further configuration
   */
  public Saml2AuthnRequestProcessorConfigurer authenticationProviders(
      final Consumer<List<AuthenticationProvider>> authenticationProvidersConsumer) {
    Assert.notNull(authenticationProvidersConsumer, "authenticationProvidersConsumer cannot be null");
    this.authenticationProvidersConsumer = authenticationProvidersConsumer;
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
  void init(final HttpSecurity httpSecurity) {
    final IdentityProviderSettings settings = Saml2ConfigurerUtils.getIdentityProviderSettings(httpSecurity);
    this.requestMatcher = new OrRequestMatcher(
        new AntPathRequestMatcher(settings.getEndpoints().getRedirectAuthnEndpoint(), HttpMethod.GET.name()),
        new AntPathRequestMatcher(settings.getEndpoints().getPostAuthnEndpoint(), HttpMethod.POST.name()));
    // TODO: HoK endpoints

    final List<AuthenticationProvider> authenticationProviders = createDefaultAuthenticationProviders(httpSecurity);
    if (!this.authenticationProviders.isEmpty()) {
      authenticationProviders.addAll(0, this.authenticationProviders);
    }
    this.authenticationProvidersConsumer.accept(authenticationProviders);
    authenticationProviders
        .forEach(authenticationProvider -> httpSecurity.authenticationProvider(postProcess(authenticationProvider)));
  }

  /** {@inheritDoc} */
  @Override
  void configure(final HttpSecurity httpSecurity) {

    final List<AuthenticationConverter> authnConverters = createDefaultAuthenticationConverters(httpSecurity);
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
        new Saml2AuthnRequestProcessingFilter(authenticationManager, this.getRequestMatcher(), authnRequestConverter);
    if (this.authenticationSuccessHandler != null) {
      filter.setAuthenticationSuccessHandler(this.authenticationSuccessHandler);
    }

    httpSecurity.addFilterBefore(postProcess(filter), AbstractPreAuthenticatedProcessingFilter.class);
  }

  /** {@inheritDoc} */
  @Override
  RequestMatcher getRequestMatcher() {
    return this.requestMatcher;
  }

  /**
   * Creates the default {@link AuthenticationConverter}s.
   * 
   * @param httpSecurity the HTTP security object
   * @return a list of {@link AuthenticationConverter} objects
   */
  protected static List<AuthenticationConverter> createDefaultAuthenticationConverters(
      final HttpSecurity httpSecurity) {
    final List<AuthenticationConverter> authenticationConverters = new ArrayList<>();

    final MetadataResolver resolver = httpSecurity.getSharedObject(MetadataResolver.class);
    authenticationConverters.add(new Saml2AuthnRequestAuthenticationConverter(resolver));

    return authenticationConverters;
  }

  /**
   * Creates the default {@link AuthenticationProvider}s.
   * 
   * @param httpSecurity the HTTP security object
   * @return a list of {@link AuthenticationProvider} objects
   */
  protected static List<AuthenticationProvider> createDefaultAuthenticationProviders(final HttpSecurity httpSecurity) {
    final List<AuthenticationProvider> authenticationProviders = new ArrayList<>();
    
    final IdentityProviderSettings settings = Saml2ConfigurerUtils.getIdentityProviderSettings(httpSecurity);

    final SignatureTrustEngine signatureTrustEngine = httpSecurity.getSharedObject(SignatureTrustEngine.class);

    final AuthnRequestValidator signatureValidator =
        new AuthnRequestSignatureValidator(signatureTrustEngine);
    
    final Saml2AuthnRequestAuthenticationProvider provider =
        new Saml2AuthnRequestAuthenticationProvider(settings, signatureValidator);
    
    final MessageReplayChecker messageReplayChecker = httpSecurity.getSharedObject(MessageReplayChecker.class);
    if (messageReplayChecker != null) {
      provider.setMessageReplayChecker(messageReplayChecker);
    }
    
    authenticationProviders.add(provider);

    return authenticationProviders;
  }

}
