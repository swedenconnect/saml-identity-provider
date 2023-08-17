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
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.xmlsec.signature.support.SignatureTrustEngine;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.util.Assert;

import se.swedenconnect.opensaml.saml2.response.replay.MessageReplayChecker;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.spring.saml.idp.attributes.DefaultPrincipalSelectionProcessor;
import se.swedenconnect.spring.saml.idp.attributes.EidasRequestedAttributeProcessor;
import se.swedenconnect.spring.saml.idp.attributes.EntityCategoryRequestedAttributeProcessor;
import se.swedenconnect.spring.saml.idp.attributes.MetadataRequestedAttributeProcessor;
import se.swedenconnect.spring.saml.idp.attributes.OasisExtensionRequestedAttributeProcessor;
import se.swedenconnect.spring.saml.idp.attributes.PrincipalSelectionProcessor;
import se.swedenconnect.spring.saml.idp.attributes.RequestedAttributeProcessor;
import se.swedenconnect.spring.saml.idp.attributes.nameid.DefaultNameIDGeneratorFactory;
import se.swedenconnect.spring.saml.idp.attributes.nameid.NameIDGenerator;
import se.swedenconnect.spring.saml.idp.attributes.nameid.NameIDGeneratorFactory;
import se.swedenconnect.spring.saml.idp.authentication.provider.UserAuthenticationProvider;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationProvider;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;
import se.swedenconnect.spring.saml.idp.authnrequest.validation.AssertionConsumerServiceValidator;
import se.swedenconnect.spring.saml.idp.authnrequest.validation.AuthnRequestEncryptCapabilitiesValidator;
import se.swedenconnect.spring.saml.idp.authnrequest.validation.AuthnRequestReplayValidator;
import se.swedenconnect.spring.saml.idp.authnrequest.validation.AuthnRequestSignatureValidator;
import se.swedenconnect.spring.saml.idp.authnrequest.validation.AuthnRequestValidator;
import se.swedenconnect.spring.saml.idp.extensions.DefaultSignatureMessageExtensionExtractor;
import se.swedenconnect.spring.saml.idp.extensions.SignatureMessageExtensionExtractor;
import se.swedenconnect.spring.saml.idp.extensions.SignatureMessagePreprocessor;
import se.swedenconnect.spring.saml.idp.settings.IdentityProviderSettings;

/**
 * A configurer for configuring the {@link Saml2AuthnRequestAuthenticationProvider}.
 *
 * @author Martin Lindström
 */
public class Saml2AuthnRequestAuthenticationProviderConfigurer
    extends AbstractObjectConfigurer<Saml2AuthnRequestAuthenticationProvider> {

  /** The signature validator. */
  private AuthnRequestValidator signatureValidator;

  /** The validator checking the AssertionConsumerService. */
  private AuthnRequestValidator assertionConsumerServiceValidator;

  /** Validator for protecting against replay attacks. */
  private AuthnRequestValidator replayValidator;

  /** Validator for checking that we can encrypt assertions. */
  private AuthnRequestValidator encryptCapabilitiesValidator;

  /**
   * A list of the {@link RequestedAttributeProcessor} instances that are used by the
   * {@link Saml2AuthnRequestAuthenticationProvider}.
   */
  private List<RequestedAttributeProcessor> requestedAttributeProcessors;

  /**
   * For customizing the {@link RequestedAttributeProcessor} instances.
   */
  private Consumer<List<RequestedAttributeProcessor>> requestedAttributeProcessorsCustomizer;

  /** Extracts the {@code SignMessage} extension. */
  private Optional<SignatureMessageExtensionExtractor> signatureMessageExtensionExtractor;

  /** Optional processor for preparing a SignMessage for display. */
  private SignatureMessagePreprocessor signatureMessagePreprocessor;

  /** Extracts the {@code PrincipalSelection} attribute values. */
  private Optional<PrincipalSelectionProcessor> principalSelectionProcessor;

  /** The {@link NameIDGeneratorFactory} to use when creating a {@link NameIDGenerator} instance. */
  private NameIDGeneratorFactory nameIDGeneratorFactory;

  /**
   * Assigns a custom {@link AuthnRequestValidator} for validating the signatures of {@link AuthnRequest} messages.
   *
   * @param signatureValidator a validator
   * @return this configurer
   */
  public Saml2AuthnRequestAuthenticationProviderConfigurer signatureValidator(
      final AuthnRequestValidator signatureValidator) {
    this.signatureValidator = Objects.requireNonNull(signatureValidator, "signatureValidator must not be null");
    return this;
  }

  /**
   * Assigns a custom assertion consumer service {@link AuthnRequestValidator}.
   * <p>
   * If the validation succeeds the validator must assigned the assertion consumer service URL using
   * {@link Saml2AuthnRequestAuthenticationToken#setAssertionConsumerServiceUrl(String)}.
   * </p>
   *
   * @param assertionConsumerServiceValidator the validator
   * @return this configurer
   */
  public Saml2AuthnRequestAuthenticationProviderConfigurer assertionConsumerServiceValidator(
      final AuthnRequestValidator assertionConsumerServiceValidator) {
    this.assertionConsumerServiceValidator =
        Objects.requireNonNull(assertionConsumerServiceValidator, "assertionConsumerServiceValidator must not be null");
    return this;
  }

  /**
   * Assigns a replay validator. The default is to use {@link AuthnRequestReplayValidator} with an in-memory
   * {@link MessageReplayChecker}. Use {@link #messageReplayChecker(MessageReplayChecker)} to configure another
   * {@link MessageReplayChecker} but stick with the {@link AuthnRequestReplayValidator}.
   *
   * @param replayValidator the validator
   * @return this configurer
   */
  public Saml2AuthnRequestAuthenticationProviderConfigurer replayValidator(
      final AuthnRequestValidator replayValidator) {
    this.replayValidator = Objects.requireNonNull(replayValidator, "replayValidator must not be null");
    return this;
  }

  /**
   * Assigns a {@link MessageReplayChecker} to the {@link AuthnRequestReplayValidator}. Mutually exlcusive with
   * {@link #replayValidator(AuthnRequestValidator)}.
   *
   * @param messageReplayChecker the message replay checker to use
   * @return this configurer
   */
  public Saml2AuthnRequestAuthenticationProviderConfigurer messageReplayChecker(
      final MessageReplayChecker messageReplayChecker) {
    Assert.notNull(messageReplayChecker, "messageReplayChecker must not be null");
    this.replayValidator = new AuthnRequestReplayValidator(messageReplayChecker);
    return this;
  }

  /**
   * Gives access to the list of {@link RequestedAttributeProcessor}s. Using this method the supplied {@link Consumer}
   * may be used to add/remove or modify the processors.
   *
   * @param customizer the customizer
   * @return this configurer
   */
  public Saml2AuthnRequestAuthenticationProviderConfigurer requestedAttributeProcessors(
      final Consumer<List<RequestedAttributeProcessor>> customizer) {
    this.requestedAttributeProcessorsCustomizer = Objects.requireNonNull(customizer, "customizer must not be null");
    return this;
  }

  /**
   * Assigns a custom {@link SignatureMessageExtensionExtractor}. The default is
   * {@link DefaultSignatureMessageExtensionExtractor}. It is possible to disable support for the
   * {@code SignMessage} extension by assigning {@code null}.
   *
   * @param signatureMessageExtensionExtractor the custom extractor (or {@code null})
   * @return this configurer
   */
  public Saml2AuthnRequestAuthenticationProviderConfigurer signatureMessageExtensionExtractor(
      final SignatureMessageExtensionExtractor signatureMessageExtensionExtractor) {
    this.signatureMessageExtensionExtractor = Optional.ofNullable(signatureMessageExtensionExtractor);
    return this;
  }

  /**
   * Assigns a {@link SignatureMessagePreprocessor} that is used to prepare received sign messages for display. By
   * default no processor is installed.
   *
   * @param signatureMessagePreprocessor the processor.
   * @return this configurer
   */
  public Saml2AuthnRequestAuthenticationProviderConfigurer signatureMessagePreprocessor(
      final SignatureMessagePreprocessor signatureMessagePreprocessor) {
    this.signatureMessagePreprocessor = signatureMessagePreprocessor;
    return this;
  }

  /**
   * Assigns a custom {@link PrincipalSelectionProcessor}. The default is {@link DefaultPrincipalSelectionProcessor}. It
   * is possible to disable support for the {@code PrincipalSelection} extension by assigning {@code null}.
   *
   * @param principalSelectionProcessor the custom principal selection extractor (or {@code null})
   * @return this configurer
   */
  public Saml2AuthnRequestAuthenticationProviderConfigurer principalSelectionProcessor(
      final PrincipalSelectionProcessor principalSelectionProcessor) {
    this.principalSelectionProcessor = Optional.ofNullable(principalSelectionProcessor);
    return this;
  }

  /**
   * Assigns a custom {@link NameIDGeneratorFactory}. The default is {@link DefaultNameIDGeneratorFactory}.
   *
   * @param nameIDGeneratorFactory the custom NameID generator factory
   * @return this configurer
   */
  public Saml2AuthnRequestAuthenticationProviderConfigurer nameIDGeneratorFactory(
      final NameIDGeneratorFactory nameIDGeneratorFactory) {
    this.nameIDGeneratorFactory =
        Objects.requireNonNull(nameIDGeneratorFactory, "nameIDGeneratorFactory must not be null");
    return this;
  }

  /** {@inheritDoc} */
  @Override
  void init(final HttpSecurity httpSecurity) {
    final IdentityProviderSettings settings = Saml2IdpConfigurerUtils.getIdentityProviderSettings(httpSecurity);

    if (this.signatureValidator == null) {
      this.signatureValidator =
          new AuthnRequestSignatureValidator(httpSecurity.getSharedObject(SignatureTrustEngine.class));
    }
    if (this.assertionConsumerServiceValidator == null) {
      this.assertionConsumerServiceValidator = new AssertionConsumerServiceValidator();
    }

    if (this.replayValidator == null) {
      this.replayValidator = new AuthnRequestReplayValidator(
          Saml2IdpConfigurerUtils.getMessageReplayChecker(httpSecurity));
    }

    this.encryptCapabilitiesValidator =
        new AuthnRequestEncryptCapabilitiesValidator(settings.getAssertionSettings().getEncryptAssertions());

    this.requestedAttributeProcessors = createDefaultRequestedAttributeProcessors(httpSecurity);
    if (this.requestedAttributeProcessorsCustomizer != null) {
      this.requestedAttributeProcessorsCustomizer.accept(this.requestedAttributeProcessors);
    }

    if (this.nameIDGeneratorFactory == null) {
      this.nameIDGeneratorFactory = new DefaultNameIDGeneratorFactory(settings.getEntityId());
    }
    httpSecurity.setSharedObject(NameIDGeneratorFactory.class, this.nameIDGeneratorFactory);

    final List<PkiCredential> decryptionCredentials = new ArrayList<>();
    Optional.ofNullable(Saml2IdpConfigurerUtils.getEncryptCredential(httpSecurity))
        .ifPresent(c -> decryptionCredentials.add(c));
    if (!decryptionCredentials.isEmpty()) {
      Optional.ofNullable(settings.getCredentials().getPreviousEncryptCredential())
          .ifPresent(c -> decryptionCredentials.add(c));
    }

    if (this.signatureMessageExtensionExtractor == null) {
      this.signatureMessageExtensionExtractor = Optional.of(
          new DefaultSignatureMessageExtensionExtractor(
              settings.getEntityId(), decryptionCredentials));
    }
    if (this.principalSelectionProcessor == null) {
      this.principalSelectionProcessor = Optional.of(new DefaultPrincipalSelectionProcessor());
    }

  }

  /** {@inheritDoc} */
  @Override
  Saml2AuthnRequestAuthenticationProvider getObject(final HttpSecurity httpSecurity) {
    final Saml2AuthnRequestAuthenticationProvider object = new Saml2AuthnRequestAuthenticationProvider(
        this.signatureValidator,
        this.assertionConsumerServiceValidator,
        this.replayValidator,
        this.encryptCapabilitiesValidator,
        this.requestedAttributeProcessors,
        this.nameIDGeneratorFactory,
        this.signatureMessageExtensionExtractor.orElse(null),
        this.principalSelectionProcessor.orElse(null));

    if (this.signatureMessagePreprocessor != null) {
      object.setSignatureMessagePreprocessor(this.signatureMessagePreprocessor);
    }

    return object;
  }

  /**
   * Gets the default set of {@link RequestedAttributeProcessor}s.
   *
   * @param httpSecurity the HTTP security object
   * @return a list of {@link RequestedAttributeProcessor}s
   */
  protected static List<RequestedAttributeProcessor> createDefaultRequestedAttributeProcessors(
      final HttpSecurity httpSecurity) {

    final List<RequestedAttributeProcessor> processors = new ArrayList<>();
    processors.add(new MetadataRequestedAttributeProcessor());
    processors.add(new OasisExtensionRequestedAttributeProcessor());
    processors.add(new EidasRequestedAttributeProcessor());

    final Collection<UserAuthenticationProvider> providers =
        Saml2IdpConfigurerUtils.getSaml2UserAuthenticationProviders(httpSecurity);

    final List<String> entityCategories = providers.stream()
        .map(UserAuthenticationProvider::getEntityCategories)
        .flatMap(Collection::stream)
        .distinct()
        .collect(Collectors.toList());

    if (!entityCategories.isEmpty()) {
      processors.add(new EntityCategoryRequestedAttributeProcessor(entityCategories));
    }

    return processors;
  }

}
