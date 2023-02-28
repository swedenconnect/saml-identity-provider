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
import java.util.Objects;

import org.opensaml.saml.saml2.core.Assertion;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.util.matcher.RequestMatcher;

import se.swedenconnect.spring.saml.idp.attributes.release.AttributeProducer;
import se.swedenconnect.spring.saml.idp.attributes.release.DefaultAttributeProducer;
import se.swedenconnect.spring.saml.idp.attributes.release.DelegatingAttributeProducer;
import se.swedenconnect.spring.saml.idp.authentication.Saml2AssertionBuilder;
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
public class Saml2UserAuthenticationConfigurer extends AbstractSaml2AuthnEndpointConfigurer {

  /** The request matcher. */
  private RequestMatcher requestMatcher;

  /** For customizing the assertions being created. */
  private Customizer<Assertion> assertionCustomizer;

  /** The ID generator for the SAML assertion builder. */
  private Saml2MessageIDGenerator idGenerator;

  /** The attribute producers used by the SAML assertion builder. */
  private List<AttributeProducer> attributeProducers = this.createDefaultAttributeProducers();

  /**
   * Constructor.
   * 
   * @param objectPostProcessor the object post processor
   */
  Saml2UserAuthenticationConfigurer(final ObjectPostProcessor<Object> objectPostProcessor) {
    super(objectPostProcessor);
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
   * Customizes the list of {@link AttributeProducer}s that will later be installed to the SAML attribute builder.
   * 
   * @param customizer a {@link Customizer}
   * @return the {@link Saml2UserAuthenticationConfigurer} for further configuration
   */
  public Saml2UserAuthenticationConfigurer attributeProducers(final Customizer<List<AttributeProducer>> customizer) {
    customizer.customize(this.attributeProducers);
    return this;
  }

  /** {@inheritDoc} */
  @Override
  protected void init(final HttpSecurity httpSecurity, final RequestMatcher requestMatcher) {
    this.requestMatcher = requestMatcher;
  }

  /** {@inheritDoc} */
  @Override
  void configure(final HttpSecurity httpSecurity) {
    final IdentityProviderSettings settings = Saml2IdpConfigurerUtils.getIdentityProviderSettings(httpSecurity);
    final AuthenticationManager authenticationManager = httpSecurity.getSharedObject(AuthenticationManager.class);
    final Saml2ResponseBuilder responseBuilder = Saml2IdpConfigurerUtils.getResponseBuilder(httpSecurity); 
    final Saml2ResponseSender responseSender = Saml2IdpConfigurerUtils.getResponseSender(httpSecurity);

    final AttributeProducer attributeProducer = this.attributeProducers.size() == 1
        ? this.attributeProducers.get(0)
        : new DelegatingAttributeProducer(this.attributeProducers);

    final Saml2AssertionBuilder assertionBuilder = new Saml2AssertionBuilder(settings.getEntityId(),
        Saml2IdpConfigurerUtils.getSignatureCredential(httpSecurity), attributeProducer);
    assertionBuilder.setNotBeforeDuration(settings.getAssertionSettings().getNotBeforeDuration());
    assertionBuilder.setNotOnOrAfterDuration(settings.getAssertionSettings().getNotOnOrAfterDuration());
    if (this.idGenerator != null) {
      assertionBuilder.setIdGenerator(idGenerator);
    }
    if (this.assertionCustomizer != null) {
      assertionBuilder.setAssertionCustomizer(this.assertionCustomizer);
    }

    final Saml2UserAuthenticationProcessingFilter filter = new Saml2UserAuthenticationProcessingFilter(
        authenticationManager, this.requestMatcher, assertionBuilder, responseBuilder, responseSender);

    httpSecurity.addFilterAfter(this.postProcess(filter), Saml2AuthnRequestProcessingFilter.class);
  }

  private List<AttributeProducer> createDefaultAttributeProducers() {
    List<AttributeProducer> producers = new ArrayList<>();
    producers.add(new DefaultAttributeProducer());
    return producers;
  }

}
