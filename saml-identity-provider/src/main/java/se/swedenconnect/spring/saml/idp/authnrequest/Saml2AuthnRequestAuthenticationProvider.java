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
package se.swedenconnect.spring.saml.idp.authnrequest;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.Assert;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorUtils;
import se.swedenconnect.opensaml.sweid.saml2.signservice.sap.SADRequest;
import se.swedenconnect.opensaml.sweid.saml2.signservice.sap.SADVersion;
import se.swedenconnect.spring.saml.idp.attributes.PrincipalSelectionProcessor;
import se.swedenconnect.spring.saml.idp.attributes.RequestedAttribute;
import se.swedenconnect.spring.saml.idp.attributes.RequestedAttributeProcessor;
import se.swedenconnect.spring.saml.idp.attributes.nameid.NameIDGenerator;
import se.swedenconnect.spring.saml.idp.attributes.nameid.NameIDGeneratorFactory;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthenticationInputToken;
import se.swedenconnect.spring.saml.idp.authnrequest.validation.AuthnRequestValidator;
import se.swedenconnect.spring.saml.idp.config.configurers.Saml2AuthnRequestAuthenticationProviderConfigurer;
import se.swedenconnect.spring.saml.idp.context.Saml2IdpContextHolder;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatus;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpException;
import se.swedenconnect.spring.saml.idp.events.Saml2IdpEventPublisher;
import se.swedenconnect.spring.saml.idp.extensions.SadRequestExtension;
import se.swedenconnect.spring.saml.idp.extensions.SignatureMessageExtension;
import se.swedenconnect.spring.saml.idp.extensions.SignatureMessageExtensionExtractor;
import se.swedenconnect.spring.saml.idp.extensions.SignatureMessagePreprocessor;
import se.swedenconnect.spring.saml.idp.response.Saml2ResponseAttributes;

/**
 * An {@link AuthenticationProvider} that processes a {@link Saml2AuthnRequestAuthenticationToken} and if the processing
 * is succesful returns a {@link Saml2UserAuthenticationInputToken}.
 * <p>
 * The signature on the authentication request is verified, and the request is checked against the IdP configuration
 * before proceeding with the actual user authentication.
 * </p>
 *
 * @author Martin Lindström
 */
@Slf4j
public class Saml2AuthnRequestAuthenticationProvider implements AuthenticationProvider {
  
  /** The event publisher. */
  private final Saml2IdpEventPublisher eventPublisher;

  /** The signature validator to use. */
  private final AuthnRequestValidator signatureValidator;

  /** The validator checking the AssertionConsumerService. */
  private final AuthnRequestValidator assertionConsumerServiceValidator;

  /** Validator for protecting against replay attacks. */
  private final AuthnRequestValidator replayValidator;

  /** Validator for asserting the we can encrypt assertions. */
  private final AuthnRequestValidator encryptCapabilitiesValidator;

  /** Extracts the requested attributes. */
  private final List<RequestedAttributeProcessor> requestedAttributesProcessors;

  /** Extracts the {@code SignMessage} extension. */
  private final SignatureMessageExtensionExtractor signatureMessageExtensionExtractor;

  /** Optional {@link SignatureMessagePreprocessor} for preparing sign messages for display. */
  private SignatureMessagePreprocessor signatureMessagePreprocessor;

  /**
   * Extracts the {@code PrincipalSelection} attribute values.
   */
  private final PrincipalSelectionProcessor principalSelectionProcessor;

  /** The {@link NameIDGeneratorFactory} to use when creating a {@link NameIDGenerator} instance. */
  private final NameIDGeneratorFactory nameIDGeneratorFactory;

  /**
   * Constructor. See {@link Saml2AuthnRequestAuthenticationProviderConfigurer} for how to configuration and setup.
   *
   * @param eventPublisher the event publisher
   * @param signatureValidator the signature validator to use
   * @param assertionConsumerServiceValidator validator checking the AssertionConsumerService
   * @param replayValidator for protecting against replay attacks
   * @param encryptCapabilitiesValidator validator asserting that we can encrypt assertions
   * @param requestedAttributesProcessors extracts the requested attributes
   * @param nameIDGeneratorFactory the {@link NameIDGeneratorFactory} to use when creating a {@link NameIDGenerator}
   *          instance
   */
  public Saml2AuthnRequestAuthenticationProvider(
      final Saml2IdpEventPublisher eventPublisher,
      final AuthnRequestValidator signatureValidator,
      final AuthnRequestValidator assertionConsumerServiceValidator,
      final AuthnRequestValidator replayValidator,
      final AuthnRequestValidator encryptCapabilitiesValidator,
      final List<RequestedAttributeProcessor> requestedAttributesProcessors,
      final NameIDGeneratorFactory nameIDGeneratorFactory) {
    this(eventPublisher, signatureValidator, assertionConsumerServiceValidator, replayValidator, 
        encryptCapabilitiesValidator, requestedAttributesProcessors, nameIDGeneratorFactory, null, null);
  }

  /**
   * Constructor. See {@link Saml2AuthnRequestAuthenticationProviderConfigurer} for how to configuration and setup.
   *
   * @param eventPublisher the event publisher
   * @param signatureValidator the signature validator to use
   * @param assertionConsumerServiceValidator validator checking the AssertionConsumerService
   * @param replayValidator for protecting against replay attacks
   * @param encryptCapabilitiesValidator validator asserting that we can encrypt assertions
   * @param requestedAttributesProcessors extracts the requested attributes
   * @param nameIDGeneratorFactory the {@link NameIDGeneratorFactory} to use when creating a {@link NameIDGenerator}
   *          instance
   * @param signatureMessageExtensionExtractor extracts the {@code SignMessage} extension (may be {@code null})
   * @param principalSelectionProcessor extracts the {@code PrincipalSelection} attribute values (may be {@code null})
   */
  public Saml2AuthnRequestAuthenticationProvider(
      final Saml2IdpEventPublisher eventPublisher,
      final AuthnRequestValidator signatureValidator,
      final AuthnRequestValidator assertionConsumerServiceValidator,
      final AuthnRequestValidator replayValidator,
      final AuthnRequestValidator encryptCapabilitiesValidator,
      final List<RequestedAttributeProcessor> requestedAttributesProcessors,
      final NameIDGeneratorFactory nameIDGeneratorFactory,
      final SignatureMessageExtensionExtractor signatureMessageExtensionExtractor,
      final PrincipalSelectionProcessor principalSelectionProcessor) {

    this.eventPublisher = Objects.requireNonNull(eventPublisher, "eventPublisher must not be null");
    this.signatureValidator = Objects.requireNonNull(signatureValidator, "signatureValidator must not be null");
    this.assertionConsumerServiceValidator =
        Objects.requireNonNull(assertionConsumerServiceValidator, "assertionConsumerServiceValidator must not be null");
    this.replayValidator = Objects.requireNonNull(replayValidator, "replayValidator must not be null");
    this.encryptCapabilitiesValidator =
        Objects.requireNonNull(encryptCapabilitiesValidator, "encryptCapabilitiesValidator must not be null");
    this.requestedAttributesProcessors = Optional.ofNullable(requestedAttributesProcessors).filter(r -> !r.isEmpty())
        .orElseThrow(() -> new IllegalArgumentException("At least one RequestedAttributeProcessor must be given"));
    this.nameIDGeneratorFactory =
        Objects.requireNonNull(nameIDGeneratorFactory, "nameIDGeneratorFactory must not be null");
    this.signatureMessageExtensionExtractor = signatureMessageExtensionExtractor;
    this.principalSelectionProcessor = principalSelectionProcessor;
  }

  /** {@inheritDoc} */
  @Override
  public Authentication authenticate(final Authentication authentication) throws AuthenticationException {

    final Saml2AuthnRequestAuthenticationToken token =
        Saml2AuthnRequestAuthenticationToken.class.cast(authentication);
    
    this.eventPublisher.publishAuthnRequestReceived(token);

    // Check message replay ...
    //
    this.replayValidator.validate(token);

    // Assert that the AssertionConsumerService information is valid ...
    //
    this.assertionConsumerServiceValidator.validate(token);
    Assert.notNull(token.getAssertionConsumerServiceUrl(),
        "ACS validator did not assign assertionConsumerServiceUrl on token");

    // Set up the response attributes - from now on we are ready to post the user back in a response.
    //
    final Saml2ResponseAttributes responseAttributes = Saml2IdpContextHolder.getContext().getResponseAttributes();
    responseAttributes.setRelayState(token.getRelayState());
    responseAttributes.setInResponseTo(token.getAuthnRequest().getID());
    responseAttributes.setDestination(token.getAssertionConsumerServiceUrl());
    responseAttributes.setPeerMetadata(token.getPeerMetadata());

    // Handle the signature on the AuthnRequest ...
    //
    this.signatureValidator.validate(token);

    // If encrypted assertions are required. Make sure the peer has such a cert ...
    //
    this.encryptCapabilitiesValidator.validate(token);

    // Check the requested NameIDPolicy, and if correct, set up a NameIDGenerator ...
    //
    final NameIDGenerator nameIDGenerator =
        this.nameIDGeneratorFactory.getNameIDGenerator(token.getAuthnRequest(), token.getPeerMetadata());
    token.setNameIDGenerator(nameIDGenerator);

    // Put together authentication requirements for the user authentication to handle ...
    //
    final AuthenticationRequirements requirements = this.createAuthenticationRequirements(token);

    // We are done using the OpenSAML context, erase it ...
    //
    token.setMessageContext(null);

    // We regard the input token as "authenticated" ...
    //
    token.setAuthenticated(true);

    return new Saml2UserAuthenticationInputToken(token, requirements);
  }

  /**
   * Supports {@link Saml2AuthnRequestAuthenticationToken}.
   */
  @Override
  public boolean supports(final Class<?> authentication) {
    return Saml2AuthnRequestAuthenticationToken.class.isAssignableFrom(authentication);
  }

  /**
   * Assigns a {@link SignatureMessagePreprocessor} for preparing the sign message for display.
   * 
   * @param signatureMessagePreprocessor a {@link SignatureMessagePreprocessor}
   */
  public void setSignatureMessagePreprocessor(final SignatureMessagePreprocessor signatureMessagePreprocessor) {
    this.signatureMessagePreprocessor = signatureMessagePreprocessor;
  }

  /**
   * Creates an {@link AuthenticationRequirements} object.
   * 
   * @param token the input token
   * @return an {@link AuthenticationRequirements} object
   * @throws Saml2ErrorStatusException for errors that should be reported back
   * @throws UnrecoverableSaml2IdpException for unrecoverable errors
   */
  protected AuthenticationRequirements createAuthenticationRequirements(
      final Saml2AuthnRequestAuthenticationToken token)
      throws Saml2ErrorStatusException, UnrecoverableSaml2IdpException {

    final boolean forceAuthn = token.getAuthnRequest().isForceAuthn();
    final boolean isPassive = token.getAuthnRequest().isPassive();

    if (forceAuthn && isPassive) {
      final String msg = "Invalid AuthnRequest - ForceAuthn and IsPassive cannot both be set";
      log.info("{} [{}]", msg, token.getLogString());
      throw new Saml2ErrorStatusException(Saml2ErrorStatus.INVALID_AUTHNREQUEST, msg);
    }
    
    final SignatureMessageExtension signMessageExtension = Optional.ofNullable(this.signatureMessageExtensionExtractor)
        .map(e -> e.extract(token))
        .orElse(null);
    if (signMessageExtension != null && this.signatureMessagePreprocessor != null) {
      final String processedMessage = this.signatureMessagePreprocessor.processSignMessage(
          signMessageExtension.getMessage(), signMessageExtension.getMimeType());
      signMessageExtension.setProcessedMessage(processedMessage);
    }
    
    SADRequest sadRequest = Optional.ofNullable(token.getAuthnRequest().getExtensions())
        .map(e -> e.getUnknownXMLObjects(SADRequest.DEFAULT_ELEMENT_NAME))
        .filter(list -> !list.isEmpty())
        .map(list -> list.get(0))
        .map(SADRequest.class::cast)
        .orElse(null);
    if (sadRequest != null) {
      if (!token.isSignatureServicePeer()) {
        log.info("Received SADRequest from non SignService SP, ignoring ... [{}]");
        sadRequest = null;
      }
      else {
        this.validateSadRequest(token, sadRequest);
      }
    }

    return AuthenticationRequirementsBuilder.builder()
        .forceAuthn(forceAuthn)
        .passiveAuthn(isPassive)
        .entityCategories(EntityDescriptorUtils.getEntityCategories(token.getPeerMetadata()))
        .requestedAttributes(this.extractRequestedAttributes(token))
        .authnContextRequirements(Optional.ofNullable(token.getAuthnRequest().getRequestedAuthnContext())
            .map(RequestedAuthnContext::getAuthnContextClassRefs)
            .map(refs -> refs.stream()
                .map(r -> r.getURI())
                .collect(Collectors.toList()))
            .orElseGet(() -> Collections.emptyList()))
        .principalSelectionAttributes(Optional.ofNullable(this.principalSelectionProcessor)
            .map(p -> p.extractPrincipalSelection(token))
            .orElseGet(() -> Collections.emptyList()))
        .signatureMessageExtension(signMessageExtension)
        .sadRequestExtension(sadRequest != null ? new SadRequestExtension(sadRequest) : null)
        .build();
  }
  
  /**
   * Validates that a received {@link SADRequest} is correct.
   * 
   * @param token the authentication request token
   * @param sadRequest the SAD request to check
   * @throws Saml2ErrorStatusException for errors
   */
  private void validateSadRequest(final Saml2AuthnRequestAuthenticationToken token, final SADRequest sadRequest) 
      throws Saml2ErrorStatusException {
    if (sadRequest.getID() == null) {
      final String msg = "Invalid AuthnRequest - Contains SADRequest extension that lacks ID field";
      log.info("{} [{}]", msg, token.getLogString());
      throw new Saml2ErrorStatusException(Saml2ErrorStatus.INVALID_AUTHNREQUEST, msg);
    }
    if (sadRequest.getRequestedVersion() != null) {
      if (!SADVersion.VERSION_10.equals(sadRequest.getRequestedVersion())) {
        final String msg = "Invalid AuthnRequest - Contains SADRequest extension that has unsupported SAD version";
        log.info("{} [{}]", msg, token.getLogString());
        throw new Saml2ErrorStatusException(Saml2ErrorStatus.INVALID_AUTHNREQUEST, msg);
      }
    }
    if (sadRequest.getDocCount() == null) {
      final String msg = "Invalid AuthnRequest - Contains SADRequest extension that lacks DocCount field";
      log.info("{} [{}]", msg, token.getLogString());
      throw new Saml2ErrorStatusException(Saml2ErrorStatus.INVALID_AUTHNREQUEST, msg);
    }
    if (sadRequest.getRequesterID() == null) {
      final String msg = "Invalid AuthnRequest - Contains SADRequest extension that lacks RequesterID field";
      log.info("{} [{}]", msg, token.getLogString());
      throw new Saml2ErrorStatusException(Saml2ErrorStatus.INVALID_AUTHNREQUEST, msg);
    }
    else if (!token.getEntityId().equals(sadRequest.getRequesterID())) {
      final String msg = "Invalid AuthnRequest - Contains SADRequest extension that has RequesterID field that does not match SP entityID";
      log.info("{} [{}]", msg, token.getLogString());
      throw new Saml2ErrorStatusException(Saml2ErrorStatus.INVALID_AUTHNREQUEST, msg);
    }
    if (sadRequest.getSignRequestID() == null) {
      final String msg = "Invalid AuthnRequest - Contains SADRequest extension that lacks SignRequestID field";
      log.info("{} [{}]", msg, token.getLogString());
      throw new Saml2ErrorStatusException(Saml2ErrorStatus.INVALID_AUTHNREQUEST, msg);
    }
  }

  /**
   * Extracts the requested attributes by invoking the configured {@link RequestedAttributeProcessor}s.
   * 
   * @param authnRequestToken the input token
   * @return a {@link Collection} of {@link RequestedAttribute}s
   */
  protected Collection<RequestedAttribute> extractRequestedAttributes(
      final Saml2AuthnRequestAuthenticationToken authnRequestToken) {

    final List<RequestedAttribute> attributes = new ArrayList<>();

    for (final RequestedAttributeProcessor p : this.requestedAttributesProcessors) {
      final Collection<RequestedAttribute> pattrs = p.extractRequestedAttributes(authnRequestToken);
      for (final RequestedAttribute r : pattrs) {
        final RequestedAttribute attr =
            attributes.stream().filter(a -> Objects.equals(a.getId(), r.getId())).findAny().orElse(null);
        if (attr != null) {
          attr.setRequired(attr.isRequired() && r.isRequired());
        }
        else {
          attributes.add(r);
        }
      }
    }

    return attributes;
  }

}
