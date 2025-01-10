/*
 * Copyright 2023-2025 Sweden Connect
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

import java.io.Serial;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.core.Authentication;

import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeConstants;
import se.swedenconnect.spring.saml.idp.attributes.PrincipalSelectionProcessor;
import se.swedenconnect.spring.saml.idp.attributes.RequestedAttribute;
import se.swedenconnect.spring.saml.idp.attributes.RequestedAttributeProcessor;
import se.swedenconnect.spring.saml.idp.attributes.nameid.NameIDGenerator;
import se.swedenconnect.spring.saml.idp.attributes.nameid.NameIDGeneratorFactory;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthenticationInputToken;
import se.swedenconnect.spring.saml.idp.authnrequest.validation.AuthnRequestValidator;
import se.swedenconnect.spring.saml.idp.context.Saml2IdpContext;
import se.swedenconnect.spring.saml.idp.context.Saml2IdpContextHolder;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatus;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;
import se.swedenconnect.spring.saml.idp.events.Saml2IdpEventPublisher;
import se.swedenconnect.spring.saml.idp.extensions.SignatureMessageExtensionExtractor;
import se.swedenconnect.spring.saml.idp.response.Saml2ResponseAttributes;
import se.swedenconnect.spring.saml.idp.settings.IdentityProviderSettings;

/**
 * Test cases for Saml2AuthnRequestAuthenticationProvider.
 *
 * @author Martin Lindström
 */
public class Saml2AuthnRequestAuthenticationProviderTest {

  private final static String ACS = "https://qa.test.swedenconnect.se/idp/profile/SAML2/Redirect/SSO";

  @BeforeEach
  public void setup() {
    Saml2IdpContextHolder.setContext(new Saml2IdpContext() {

      @Serial
      private static final long serialVersionUID = 1073524114587524137L;

      final IdentityProviderSettings settings = IdentityProviderSettings.builder().build();
      final Saml2ResponseAttributes responseAttributes = new Saml2ResponseAttributes();

      @Override
      public IdentityProviderSettings getSettings() {
        return this.settings;
      }

      @Override
      public Saml2ResponseAttributes getResponseAttributes() {
        return this.responseAttributes;
      }
    });
  }

  @AfterEach
  public void cleanup() {
    Saml2IdpContextHolder.resetContext();
  }

  @Test
  public void testSuccess() {

    final AuthnRequestValidator signatureValidator = Mockito.mock(AuthnRequestValidator.class);

    final AuthnRequestValidator assertionConsumerServiceValidator = Mockito.mock(AuthnRequestValidator.class);
    Mockito.doAnswer(invocation -> {
      final Saml2AuthnRequestAuthenticationToken t = invocation.getArgument(0);
      t.setAssertionConsumerServiceUrl(ACS);
      return null;
    }).when(assertionConsumerServiceValidator).validate(Mockito.any());

    final AuthnRequestValidator replayValidator = Mockito.mock(AuthnRequestValidator.class);
    final AuthnRequestValidator encryptCapabilitiesValidator = Mockito.mock(AuthnRequestValidator.class);

    final RequestedAttributeProcessor requestedAttributeProcessor = Mockito.mock(RequestedAttributeProcessor.class);
    Mockito.when(requestedAttributeProcessor.extractRequestedAttributes(Mockito.any()))
        .thenReturn(List.of(
            new RequestedAttribute(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER,
                AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_PERSONAL_IDENTITY_NUMBER,
                true),
            new RequestedAttribute(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER,
                AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_PERSONAL_IDENTITY_NUMBER,
                false),
            new RequestedAttribute(AttributeConstants.ATTRIBUTE_NAME_DISPLAY_NAME,
                AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_DISPLAY_NAME,
                true),
            new RequestedAttribute(AttributeConstants.ATTRIBUTE_NAME_DISPLAY_NAME,
                AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_DISPLAY_NAME,
                true)));

    final NameIDGeneratorFactory nameIDGeneratorFactory = Mockito.mock(NameIDGeneratorFactory.class);
    Mockito.when(nameIDGeneratorFactory.getNameIDGenerator(Mockito.any(), Mockito.any()))
        .thenReturn(Mockito.mock(NameIDGenerator.class));

    final SignatureMessageExtensionExtractor signatureMessageExtensionExtractor =
        Mockito.mock(SignatureMessageExtensionExtractor.class);
    final PrincipalSelectionProcessor principalSelectionProcessor = Mockito.mock(PrincipalSelectionProcessor.class);

    final Saml2IdpEventPublisher publisher = new Saml2IdpEventPublisher(Mockito.mock(ApplicationEventPublisher.class));

    final Saml2AuthnRequestAuthenticationProvider provider = new Saml2AuthnRequestAuthenticationProvider(
        publisher, signatureValidator, assertionConsumerServiceValidator, replayValidator,
        encryptCapabilitiesValidator, List.of(requestedAttributeProcessor), nameIDGeneratorFactory,
        entityDescriptor -> true,
        signatureMessageExtensionExtractor, principalSelectionProcessor);

    Assertions.assertTrue(provider.supports(Saml2AuthnRequestAuthenticationToken.class));

    final AuthnRequest authnRequest = Mockito.mock(AuthnRequest.class);
    Mockito.when(authnRequest.getID()).thenReturn("ID");

    final Saml2AuthnRequestAuthenticationToken token =
        new Saml2AuthnRequestAuthenticationToken(authnRequest, "the-relay-state");
    token.setPeerMetadata(Mockito.mock(EntityDescriptor.class));

    final Authentication a = provider.authenticate(token);
    Assertions.assertTrue(a instanceof Saml2UserAuthenticationInputToken);

    final Saml2ResponseAttributes responseAttributes = Saml2IdpContextHolder.getContext().getResponseAttributes();
    Assertions.assertNotNull(responseAttributes);
    Assertions.assertEquals("the-relay-state", responseAttributes.getRelayState());
    Assertions.assertEquals("ID", responseAttributes.getInResponseTo());
    Assertions.assertNotNull(responseAttributes.getPeerMetadata());
    Assertions.assertEquals(ACS, responseAttributes.getDestination());

    final Saml2UserAuthenticationInputToken inputToken = (Saml2UserAuthenticationInputToken) a;
    Assertions.assertEquals(2, inputToken.getAuthnRequirements().getRequestedAttributes().size());
    final RequestedAttribute ra1 = inputToken.getAuthnRequirements().getRequestedAttributes().stream()
        .filter(r -> r.getId().equals(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER))
        .findFirst()
        .orElse(null);
    Assertions.assertNotNull(ra1);
    Assertions.assertFalse(ra1.isRequired());

    final RequestedAttribute ra2 = inputToken.getAuthnRequirements().getRequestedAttributes().stream()
        .filter(r -> r.getId().equals(AttributeConstants.ATTRIBUTE_NAME_DISPLAY_NAME))
        .findFirst()
        .orElse(null);
    Assertions.assertNotNull(ra2);
    Assertions.assertTrue(ra2.isRequired());

    Assertions.assertNotNull(token.getNameIDGenerator());
  }

  @Test
  void testNotAuthorized() {

    final AuthnRequestValidator signatureValidator = Mockito.mock(AuthnRequestValidator.class);

    final AuthnRequestValidator assertionConsumerServiceValidator = Mockito.mock(AuthnRequestValidator.class);
    Mockito.doAnswer(invocation -> {
      final Saml2AuthnRequestAuthenticationToken t = invocation.getArgument(0);
      t.setAssertionConsumerServiceUrl(ACS);
      return null;
    }).when(assertionConsumerServiceValidator).validate(Mockito.any());

    final AuthnRequestValidator replayValidator = Mockito.mock(AuthnRequestValidator.class);
    final AuthnRequestValidator encryptCapabilitiesValidator = Mockito.mock(AuthnRequestValidator.class);

    final RequestedAttributeProcessor requestedAttributeProcessor = Mockito.mock(RequestedAttributeProcessor.class);
    Mockito.when(requestedAttributeProcessor.extractRequestedAttributes(Mockito.any()))
        .thenReturn(List.of(
            new RequestedAttribute(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER,
                AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_PERSONAL_IDENTITY_NUMBER,
                true),
            new RequestedAttribute(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER,
                AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_PERSONAL_IDENTITY_NUMBER,
                false),
            new RequestedAttribute(AttributeConstants.ATTRIBUTE_NAME_DISPLAY_NAME,
                AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_DISPLAY_NAME,
                true),
            new RequestedAttribute(AttributeConstants.ATTRIBUTE_NAME_DISPLAY_NAME,
                AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_DISPLAY_NAME,
                true)));

    final NameIDGeneratorFactory nameIDGeneratorFactory = Mockito.mock(NameIDGeneratorFactory.class);
    Mockito.when(nameIDGeneratorFactory.getNameIDGenerator(Mockito.any(), Mockito.any()))
        .thenReturn(Mockito.mock(NameIDGenerator.class));

    final Saml2IdpEventPublisher publisher = new Saml2IdpEventPublisher(Mockito.mock(ApplicationEventPublisher.class));

    final Saml2AuthnRequestAuthenticationProvider provider = new Saml2AuthnRequestAuthenticationProvider(
        publisher, signatureValidator, assertionConsumerServiceValidator, replayValidator,
        encryptCapabilitiesValidator, List.of(requestedAttributeProcessor), nameIDGeneratorFactory,
        entityDescriptor -> false, null, null);

    final AuthnRequest authnRequest = Mockito.mock(AuthnRequest.class);
    Mockito.when(authnRequest.getID()).thenReturn("ID");
    final Issuer issuer = Mockito.mock(Issuer.class);
    Mockito.when(issuer.getValue()).thenReturn("issuer");
    Mockito.when(authnRequest.getIssuer()).thenReturn(issuer);

    final Saml2AuthnRequestAuthenticationToken token =
        new Saml2AuthnRequestAuthenticationToken(authnRequest, "the-relay-state");

    final EntityDescriptor entityDescriptor = Mockito.mock(EntityDescriptor.class);
    Mockito.when(entityDescriptor.getEntityID()).thenReturn("ID");
    token.setPeerMetadata(entityDescriptor);

    final Saml2ErrorStatusException error =
        Assertions.assertThrows(Saml2ErrorStatusException.class, () -> provider.authenticate(token));
    Assertions.assertEquals(Saml2ErrorStatus.NOT_AUTHORIZED.getDefaultStatusMessage(), error.getMessage());

  }

}
