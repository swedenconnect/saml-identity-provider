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
package se.swedenconnect.spring.saml.idp.config.configurers;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import org.opensaml.saml.saml2.core.Assertion;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import jakarta.servlet.http.HttpServletRequest;
import se.swedenconnect.spring.saml.idp.attributes.release.AttributeProducer;
import se.swedenconnect.spring.saml.idp.attributes.release.AttributeReleaseManager;
import se.swedenconnect.spring.saml.idp.attributes.release.AttributeReleaseVoter;
import se.swedenconnect.spring.saml.idp.attributes.release.DefaultAttributeReleaseManager;
import se.swedenconnect.spring.saml.idp.attributes.release.IncludeAllAttributeReleaseVoter;
import se.swedenconnect.spring.saml.idp.attributes.release.SwedenConnectAttributeProducer;
import se.swedenconnect.spring.saml.idp.attributes.release.SwedenConnectAttributeReleaseVoter;
import se.swedenconnect.spring.saml.idp.authentication.DelegatingPostAuthenticationProcessor;
import se.swedenconnect.spring.saml.idp.authentication.PostAuthenticationProcessor;
import se.swedenconnect.spring.saml.idp.authentication.Saml2AssertionBuilder;
import se.swedenconnect.spring.saml.idp.authentication.SwedenConnectPostAuthenticationProcessor;
import se.swedenconnect.spring.saml.idp.authentication.provider.external.AbstractUserRedirectAuthenticationProvider;
import se.swedenconnect.spring.saml.idp.authentication.provider.external.ExternalAuthenticatorTokenRepository;
import se.swedenconnect.spring.saml.idp.authentication.provider.external.FilterAuthenticationTokenRepository;
import se.swedenconnect.spring.saml.idp.authentication.provider.external.SessionBasedExternalAuthenticationRepository;
import se.swedenconnect.spring.saml.idp.response.Saml2ResponseBuilder;
import se.swedenconnect.spring.saml.idp.response.Saml2ResponseSender;
import se.swedenconnect.spring.saml.idp.settings.IdentityProviderSettings;
import se.swedenconnect.spring.saml.idp.utils.Saml2MessageIDGenerator;
import se.swedenconnect.spring.saml.idp.web.filters.Saml2AuthnRequestProcessingFilter;
import se.swedenconnect.spring.saml.idp.web.filters.Saml2UserAuthenticationProcessingFilter;

/**
 * A configurer for handling user authentication and issuance of SAML {@link Assertion}s.
 *
 * @author Martin Lindström
 */
public class Saml2UserAuthenticationConfigurer extends AbstractSaml2Configurer {

  /** The request matcher for processing authentication requests. */
  private RequestMatcher authnRequestRequestMatcher;

  /** Request matcher for resuming authentication after redirecting the user agent for authentication. */
  private DeferredRequestMatcher resumeAuthnRequestMatcher = new DeferredRequestMatcher();

  /** For customizing the assertions being created. */
  private Customizer<Assertion> assertionCustomizer;

  /** The ID generator for the SAML assertion builder. */
  private Saml2MessageIDGenerator idGenerator;

  /** The attribute producers used by the {@link AttributeReleaseManager} (and SAML assertion builder). */
  private List<AttributeProducer> attributeProducers = this.createDefaultAttributeProducers();

  /** The attribute release voters used by the {@link AttributeReleaseManager} (and SAML assertion builder). */
  private List<AttributeReleaseVoter> attributeReleaseVoters = this.createDefaultAttributeReleaseVoters();

  /** The post authentication processors. */
  private List<PostAuthenticationProcessor> postAuthenticationProcessors =
      this.createDefaultPostAuthenticationProcessors();

  /** Repository storing authentication objects used for external authentication. */
  private FilterAuthenticationTokenRepository authenticationTokenRepository;

  /**
   * Constructor.
   *
   * @param objectPostProcessor the object post processor
   */
  Saml2UserAuthenticationConfigurer(final ObjectPostProcessor<Object> objectPostProcessor) {
    super(objectPostProcessor);
  }

  public Saml2UserAuthenticationConfigurer resumeAuthnPath(final String path) {
    this.resumeAuthnRequestMatcher.addPath(Objects.requireNonNull(path, "path must not be null"));
    return this;
  }

  /**
   * Assigns a {@link FilterAuthenticationTokenRepository} instance for storing {@link Authentication} objects when
   * external authentication is used. The default is {@link SessionBasedExternalAuthenticationRepository}.
   * <p>
   * Note: Ensure that the {@link ExternalAuthenticatorTokenRepository} assigned to the
   * {@link AbstractUserRedirectAuthenticationProvider} is using the same persistence strategy as the assigned
   * repository bean.
   * </p>
   *
   * @param authenticationTokenRepository the repository to use
   * @return the {@link Saml2UserAuthenticationConfigurer} for further configuration
   */
  public Saml2UserAuthenticationConfigurer authenticationTokenRepository(
      final FilterAuthenticationTokenRepository authenticationTokenRepository) {
    this.authenticationTokenRepository =
        Objects.requireNonNull(authenticationTokenRepository, "authenticationTokenRepository must not be null");
    return this;
  }

  /**
   * By assigning a {@link Customizer} the {@link Assertion} object that is built can be modified. The customizer is
   * invoked when the {@link Assertion} object has been completely built, but before it is signed.
   *
   * @param assertionCustomizer a {@link Customizer}
   * @return the {@link Saml2UserAuthenticationConfigurer} for further configuration
   */
  public Saml2UserAuthenticationConfigurer assertionCustomizer(final Customizer<Assertion> assertionCustomizer) {
    this.assertionCustomizer = Objects.requireNonNull(assertionCustomizer, "assertionCustomizer must not be null");
    return this;
  }

  /**
   * Assigns a custom {@link Saml2MessageIDGenerator} to be used by the assertion builder.
   *
   * @param idGenerator the {@link Saml2MessageIDGenerator}
   * @return the {@link Saml2UserAuthenticationConfigurer} for further configuration
   */
  public Saml2UserAuthenticationConfigurer idGenerator(final Saml2MessageIDGenerator idGenerator) {
    this.idGenerator = Objects.requireNonNull(idGenerator, "idGenerator must not be null");
    return this;
  }

  /**
   * Customizes the list of {@link AttributeProducer}s that will later be installed to the
   * {@link AttributeReleaseManager} and SAML attribute builder.
   *
   * @param customizer a {@link Customizer}
   * @return the {@link Saml2UserAuthenticationConfigurer} for further configuration
   */
  public Saml2UserAuthenticationConfigurer attributeProducers(final Customizer<List<AttributeProducer>> customizer) {
    customizer.customize(this.attributeProducers);
    return this;
  }

  /**
   * Customizes the list of {@link AttributeReleaseVoter}s that will later be installed to the
   * {@link AttributeReleaseManager} and SAML attribute builder.
   *
   * @param customizer a {@link Customizer}
   * @return the {@link Saml2UserAuthenticationConfigurer} for further configuration
   */
  public Saml2UserAuthenticationConfigurer attributeReleaseVoters(
      final Customizer<List<AttributeReleaseVoter>> customizer) {
    customizer.customize(this.attributeReleaseVoters);
    return this;
  }

  /**
   * Customizes the list of {@link PostAuthenticationProcessor}s.
   *
   * @param customizer a {@link Customizer}
   * @return the {@link Saml2UserAuthenticationConfigurer} for further configuration
   */
  public Saml2UserAuthenticationConfigurer postAuthenticationProcessors(
      final Customizer<List<PostAuthenticationProcessor>> customizer) {
    customizer.customize(this.postAuthenticationProcessors);
    return this;
  }

  /** {@inheritDoc} */
  @Override
  protected void init(final HttpSecurity httpSecurity) {
    this.authnRequestRequestMatcher = Saml2IdpConfigurerUtils.getAuthnEndpointsRequestMatcher(httpSecurity);
  }

  /** {@inheritDoc} */
  @Override
  void configure(final HttpSecurity httpSecurity) {
    final IdentityProviderSettings settings = Saml2IdpConfigurerUtils.getIdentityProviderSettings(httpSecurity);
    final AuthenticationManager authenticationManager = httpSecurity.getSharedObject(AuthenticationManager.class);
    final Saml2ResponseBuilder responseBuilder = Saml2IdpConfigurerUtils.getResponseBuilder(httpSecurity);
    final Saml2ResponseSender responseSender = Saml2IdpConfigurerUtils.getResponseSender(httpSecurity);

    // Assign SAD factory ...
    //
    for (final AttributeProducer p : this.attributeProducers) {
      if (p instanceof SwedenConnectAttributeProducer) {
        final SwedenConnectAttributeProducer scap = (SwedenConnectAttributeProducer) p;
        if (scap.getSadFactory() == null) {
          scap.setSadFactory(Saml2IdpConfigurerUtils.getSadFactory(httpSecurity));
        }
      }
    }

    final AttributeReleaseManager attributeReleaseManager =
        new DefaultAttributeReleaseManager(this.attributeProducers, this.attributeReleaseVoters);

    final Saml2AssertionBuilder assertionBuilder = new Saml2AssertionBuilder(settings.getEntityId(),
        Saml2IdpConfigurerUtils.getSignatureCredential(httpSecurity), attributeReleaseManager);
    assertionBuilder.setNotBeforeDuration(settings.getAssertionSettings().getNotBeforeDuration());
    assertionBuilder.setNotOnOrAfterDuration(settings.getAssertionSettings().getNotOnOrAfterDuration());
    if (this.idGenerator != null) {
      assertionBuilder.setIdGenerator(this.idGenerator);
    }
    if (this.assertionCustomizer != null) {
      assertionBuilder.setAssertionCustomizer(this.assertionCustomizer);
    }

    final PostAuthenticationProcessor postAuthenticationProcessor = this.postAuthenticationProcessors.size() == 1
        ? this.postAuthenticationProcessors.get(0)
        : new DelegatingPostAuthenticationProcessor(this.postAuthenticationProcessors);

    final Saml2UserAuthenticationProcessingFilter filter = new Saml2UserAuthenticationProcessingFilter(
        authenticationManager, this.authnRequestRequestMatcher, postAuthenticationProcessor,
        assertionBuilder, responseBuilder, responseSender, Saml2IdpConfigurerUtils.getEventPublisher(httpSecurity));

    if (this.resumeAuthnRequestMatcher.isConfigured()) {
      filter.setResumeAuthnRequestMatcher(this.resumeAuthnRequestMatcher);
    }
    if (this.authenticationTokenRepository != null) {
      filter.setAuthenticationTokenRepository(this.authenticationTokenRepository);
    }

    httpSecurity.addFilterAfter(this.postProcess(filter), Saml2AuthnRequestProcessingFilter.class);
  }

  /** {@inheritDoc} */
  @Override
  RequestMatcher getRequestMatcher() {
    return this.resumeAuthnRequestMatcher;
  }

  private List<AttributeProducer> createDefaultAttributeProducers() {
    List<AttributeProducer> producers = new ArrayList<>();
    producers.add(new SwedenConnectAttributeProducer());
    return producers;
  }

  private List<AttributeReleaseVoter> createDefaultAttributeReleaseVoters() {
    List<AttributeReleaseVoter> voters = new ArrayList<>();
    voters.add(new IncludeAllAttributeReleaseVoter());
    voters.add(new SwedenConnectAttributeReleaseVoter());
    return voters;
  }

  private List<PostAuthenticationProcessor> createDefaultPostAuthenticationProcessors() {
    List<PostAuthenticationProcessor> processors = new ArrayList<>();
    processors.add(new SwedenConnectPostAuthenticationProcessor());
    return processors;
  }

  private static class DeferredRequestMatcher implements RequestMatcher {

    private List<String> paths = new ArrayList<>();

    private RequestMatcher matcher = new NegatedRequestMatcher(AnyRequestMatcher.INSTANCE);

    @Override
    public boolean matches(final HttpServletRequest request) {
      return this.matcher.matches(request);
    }

    public void addPath(final String path) {
      this.paths.add(Objects.requireNonNull(path, "path must not be null"));
      if (this.paths.size() == 1) {
        this.matcher = new AntPathRequestMatcher(path);
      }
      else {
        this.matcher = new OrRequestMatcher(this.paths.stream()
            .map(p -> (RequestMatcher) new AntPathRequestMatcher(p))
            .toList());

      }
    }

    public boolean isConfigured() {
      return !this.paths.isEmpty();
    }

  }

}
