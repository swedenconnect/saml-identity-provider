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

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.Assert;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorUtils;
import se.swedenconnect.opensaml.saml2.response.replay.InMemoryReplayChecker;
import se.swedenconnect.opensaml.saml2.response.replay.MessageReplayChecker;
import se.swedenconnect.spring.saml.idp.attributes.DefaultPrincipalSelectionProcessor;
import se.swedenconnect.spring.saml.idp.attributes.DelegatingRequestedAttributeProcessor;
import se.swedenconnect.spring.saml.idp.attributes.EidasRequestedAttributeProcessor;
import se.swedenconnect.spring.saml.idp.attributes.EntityCategoryRequestedAttributeProcessor;
import se.swedenconnect.spring.saml.idp.attributes.MetadataRequestedAttributeProcessor;
import se.swedenconnect.spring.saml.idp.attributes.OasisExtensionRequestedAttributeProcessor;
import se.swedenconnect.spring.saml.idp.attributes.PrincipalSelectionProcessor;
import se.swedenconnect.spring.saml.idp.attributes.RequestedAttribute;
import se.swedenconnect.spring.saml.idp.attributes.RequestedAttributeProcessor;
import se.swedenconnect.spring.saml.idp.attributes.UserAttribute;
import se.swedenconnect.spring.saml.idp.authnrequest.validation.AssertionConsumerServiceValidator;
import se.swedenconnect.spring.saml.idp.authnrequest.validation.AuthnRequestReplayValidator;
import se.swedenconnect.spring.saml.idp.authnrequest.validation.AuthnRequestValidator;
import se.swedenconnect.spring.saml.idp.context.Saml2IdpContextHolder;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatus;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpException;
import se.swedenconnect.spring.saml.idp.extensions.DefaultSignatureMessageExtensionExtractor;
import se.swedenconnect.spring.saml.idp.extensions.SignatureMessageExtension;
import se.swedenconnect.spring.saml.idp.extensions.SignatureMessageExtensionExtractor;
import se.swedenconnect.spring.saml.idp.response.Saml2ResponseAttributes;
import se.swedenconnect.spring.saml.idp.settings.IdentityProviderSettings;
import se.swedenconnect.spring.saml.idp.utils.Saml2IdentityProviderVersion;

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

  /** The signature validator to use. */
  private AuthnRequestValidator signatureValidator;

  /** The validator checking the AssertionConsumerService. */
  private AuthnRequestValidator assertionConsumerServiceValidator;

  /** Validator for protecting against replay attacks. */
  private AuthnRequestValidator replayValidator;
  private Supplier<AuthnRequestValidator> replayValidatorSupplier;

  /** Extracts the requested attributes. */
  private RequestedAttributeProcessor requestedAttributesProcessor;

  /** Extracts the {@code SignMessage} extension. */
  private SignatureMessageExtensionExtractor signatureMessageExtensionExtractor;

  /**
   * Extracts the {@code PrincipalSelection} attribute values.
   */
  private PrincipalSelectionProcessor principalSelectionProcessor;

  /**
   * Constructor.
   * 
   * @param settings the IdP settings
   * @param signatureValidator the signature validator to use
   */
  public Saml2AuthnRequestAuthenticationProvider(
      final IdentityProviderSettings settings,
      final AuthnRequestValidator signatureValidator) {
    Assert.notNull(settings, "settings must not be null");
    this.signatureValidator = Objects.requireNonNull(signatureValidator, "signatureValidator must not be null");
    this.assertionConsumerServiceValidator = new AssertionConsumerServiceValidator();
    this.replayValidatorSupplier = () -> {
      if (this.replayValidator == null) {
        this.replayValidator = new AuthnRequestReplayValidator();
      }
      return this.replayValidator;
    };
    this.requestedAttributesProcessor = new DelegatingRequestedAttributeProcessor(List.of(
        new MetadataRequestedAttributeProcessor(), new OasisExtensionRequestedAttributeProcessor(),
        new EidasRequestedAttributeProcessor(), new EntityCategoryRequestedAttributeProcessor(settings)));
    this.signatureMessageExtensionExtractor = new DefaultSignatureMessageExtensionExtractor(settings);
    this.principalSelectionProcessor = new DefaultPrincipalSelectionProcessor();
  }

  /**
   * Assigns a custom {@link AuthnRequestValidator} overriding the default for signature validation.
   * 
   * @param signatureValidator the signature validator to use
   */
  public void setSignatureValidator(final AuthnRequestValidator signatureValidator) {
    this.signatureValidator = Objects.requireNonNull(signatureValidator, "signatureValidator must not be null");
  }

  /**
   * Assigns a custom {@link AuthnRequestValidator} overriding the default validator for checking assertion consumer
   * service.
   * 
   * @param assertionConsumerServiceValidator validator for assertion consumer service
   */
  public void setAssertionConsumerServiceValidator(final AuthnRequestValidator assertionConsumerServiceValidator) {
    Assert.notNull(assertionConsumerServiceValidator, "assertionConsumerServiceValidator must not be null");
    this.assertionConsumerServiceValidator = assertionConsumerServiceValidator;
  }

  /**
   * Assigns a {@link MessageReplayChecker} for handling message replay detection. If none is provided a
   * {@link InMemoryReplayChecker} will be used.
   * 
   * @param messageReplayChecker the message replay checker
   */
  public void setMessageReplayChecker(final MessageReplayChecker messageReplayChecker) {
    this.replayValidator = new AuthnRequestReplayValidator(
        Objects.requireNonNull(messageReplayChecker, "messageReplayChecker must not be null"));
  }

  /**
   * Assigns a custom {@link RequestedAttributeProcessor}. The default is an
   * {@link DelegatingRequestedAttributeProcessor} instance using the following processors:
   * <ul>
   * <li>{@link MetadataRequestedAttributeProcessor} - for finding requested attributes from an
   * {@code AttributeConsumingService} element in the Service Provider metadata.</li>
   * <li>{@link OasisExtensionRequestedAttributeProcessor} - for finding requested attributes appearing in the
   * {@link org.opensaml.saml.ext.reqattr.RequestedAttributes} extension of the {@link AuthnRequest}.</li>
   * <li>{@link EidasRequestedAttributeProcessor} - for finding requested attributes appearing in the eIDAS
   * {@link se.litsec.eidas.opensaml.ext.RequestedAttributes} extension of the {@link AuthnRequest}.</li>
   * <li>{@link EntityCategoryRequestedAttributeProcessor} - for finding requested attributes based on declared entity
   * categories.</li>
   * </ul>
   * 
   * @param requestedAttributesProcessor the processor
   */
  public void setRequestedAttributeProcessor(final RequestedAttributeProcessor requestedAttributesProcessor) {
    this.requestedAttributesProcessor =
        Objects.requireNonNull(requestedAttributesProcessor, "requestedAttributesProcessor must not be null");
  }

  /**
   * Assigns a custom {@link SignatureMessageExtensionExtractor}. The default is
   * {@link DefaultSignatureMessageExtensionExtractor}.
   * 
   * @param signatureMessageExtensionExtractor the custom extractor
   */
  public void setSignatureMessageExtensionExtractor(
      final SignatureMessageExtensionExtractor signatureMessageExtensionExtractor) {
    this.signatureMessageExtensionExtractor = Objects.requireNonNull(signatureMessageExtensionExtractor,
        "signatureMessageExtensionExtractor must not be null");
  }

  /**
   * Assigns a custom {@link PrincipalSelectionProcessor}. The default is {@link DefaultPrincipalSelectionProcessor}.
   * 
   * @param principalSelectionProcessor the custom principal selection extractor
   */
  public void setPrincipalSelectionProcessor(final PrincipalSelectionProcessor principalSelectionProcessor) {
    this.principalSelectionProcessor =
        Objects.requireNonNull(principalSelectionProcessor, "principalSelectionProcessor must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public Authentication authenticate(final Authentication authentication) throws AuthenticationException {

    final Saml2AuthnRequestAuthenticationToken token =
        Saml2AuthnRequestAuthenticationToken.class.cast(authentication);

    // Check message replay ...
    //
    this.replayValidatorSupplier.get().validate(token);

    // Assert that the AssertionConsumerService information is valid ...
    //
    this.assertionConsumerServiceValidator.validate(token);
    Assert.notNull(token.getAssertionConsumerServiceUrl(),
        "ACS validator did not assign assertionConsumerServiceUrl on token");

    try {

      // Handle the signature on the AuthnRequest ...
      //
      this.signatureValidator.validate(token);

      // OK, proceed checking the message
      // TODO

      // Get attribute consumer service
      //
//    SAMLAddAttributeConsumingServiceHandler
      // TODO: handle eIDAS requested attributes extension ...

      // SSO check?
      // SecurityContextHolder.getContext().

      // Put together authentication requirements for the user authentication to handle ...
      //

      // We are done using the OpenSAML context, erase it ...
      token.setMessageContext(null);

      token.setAuthenticated(true);

      final AuthenticationRequirements requirements = this.createAuthenticationRequirements(token);
            
      final Saml2UserAuthenticationInputToken inputToken = new Saml2UserAuthenticationInputToken(token, requirements);
      
      return inputToken;
    }
    catch (final Saml2ErrorStatusException e) {
      // Make sure the error handler knows where to send the error response ...
      //
      final Saml2ResponseAttributes responseAttributes = Saml2IdpContextHolder.getContext().getResponseAttributes();
      responseAttributes.setRelayState(token.getRelayState());
      responseAttributes.setInResponseTo(token.getAuthnRequest().getID());
      responseAttributes.setDestination(token.getAssertionConsumerServiceUrl());
      responseAttributes.setPeerMetadata(token.getPeerMetadata());
      
      throw e;
    }
  }

  protected AuthenticationRequirements createAuthenticationRequirements(
      final Saml2AuthnRequestAuthenticationToken token)
      throws Saml2ErrorStatusException, UnrecoverableSaml2IdpException {

    final boolean forceAuthn = token.getAuthnRequest().isForceAuthn();
    final boolean isPassive = token.getAuthnRequest().isPassive();

    if (forceAuthn && isPassive) {
      final String msg = "Invalid AuthnRequest - ForceAuthn and IsPassive cannot both be set";
      log.info("{} {}", msg, token.getLogString());
      throw new Saml2ErrorStatusException(Saml2ErrorStatus.INVALID_AUTHNREQUEST, msg);
    }

    final Collection<String> entityCategories = EntityDescriptorUtils.getEntityCategories(token.getPeerMetadata());
    final Collection<RequestedAttribute> requestedAttributes =
        this.requestedAttributesProcessor.extractRequestedAttributes(token);

    // TODO: will be changed
    final Collection<String> authnContextUris = Optional.ofNullable(token.getAuthnRequest().getRequestedAuthnContext())
        .map(RequestedAuthnContext::getAuthnContextClassRefs)
        .map(refs -> refs.stream()
            .map(r -> r.getURI())
            .collect(Collectors.toList()))
        .orElseGet(() -> Collections.emptyList());

    final Collection<UserAttribute> principalSelectionAttributes =
        this.principalSelectionProcessor.extractPrincipalSelection(token);

    final SignatureMessageExtension signMessageExtension = this.signatureMessageExtensionExtractor.extract(token);

    return new AuthenticationRequirements() {

      private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

      @Override
      public boolean isForceAuthn() {
        return forceAuthn;
      }

      @Override
      public boolean isPassiveAuthn() {
        return isPassive;
      }

      @Override
      public Collection<String> getEntityCategories() {
        return entityCategories;
      }

      @Override
      public Collection<RequestedAttribute> getRequestedAttribute() {
        return requestedAttributes;
      }

      @Override
      public Collection<String> getAuthnContextRequirements() {
        return authnContextUris;
      }

      @Override
      public Collection<UserAttribute> getPrincipalSelectionAttributes() {
        return principalSelectionAttributes;
      }

      @Override
      public SignatureMessageExtension getSignatureMessageExtension() {
        return signMessageExtension;
      }

    };
  }

  /*
   * Rule concerning extracting requested attributes given declared entity categories. Step 1: Find all service entity
   * categories declared by the SP. Step 2: Remove those service entity categories not declared by the IdP. Step 3: If
   * only one SEC left. Add the attributes to the normal list ... Otherwise, add all attributes, but set
   * isRequired=false
   * 
   */

  /**
   * Supports {@link Saml2AuthnRequestAuthenticationToken}.
   */
  @Override
  public boolean supports(final Class<?> authentication) {
    return Saml2AuthnRequestAuthenticationToken.class.isAssignableFrom(authentication);
  }

}
