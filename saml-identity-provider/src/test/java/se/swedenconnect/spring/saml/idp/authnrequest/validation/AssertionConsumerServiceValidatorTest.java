/*
 * Copyright 2023-2026 Sweden Connect
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
package se.swedenconnect.spring.saml.idp.authnrequest.validation;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;

import se.swedenconnect.opensaml.saml2.metadata.build.AssertionConsumerServiceBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.EntityDescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.SPSSODescriptorBuilder;
import se.swedenconnect.spring.saml.idp.OpenSamlTestBase;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpError;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpException;

/**
 * Test cases for AssertionConsumerServiceValidator.
 *
 * @author Martin Lindström
 */
public class AssertionConsumerServiceValidatorTest extends OpenSamlTestBase {

  /** The SP entity ID. */
  private static final String SP_ENTITY_ID = "https://sp.example.com";

  /** Location of the AssertionConsumerService having index 0. */
  private static final String ACS_0 = "https://sp.example.com/acs/post";

  /** Location of the AssertionConsumerService having index 1, which is the default. */
  private static final String ACS_1 = "https://sp.example.com/acs/post2";

  /** Location of the AssertionConsumerService having index 2. */
  private static final String ACS_2 = "https://sp.example.com/acs/redirect";

  /** The validator under test. */
  private final AssertionConsumerServiceValidator validator = new AssertionConsumerServiceValidator();

  @Test
  public void testIndexOnly() {
    final Saml2AuthnRequestAuthenticationToken token = this.token(2, null, null);

    this.validator.validate(token);

    Assertions.assertEquals(ACS_2, token.getAssertionConsumerServiceUrl());
  }

  @Test
  public void testIndexNotInMetadata() {
    this.assertInvalidAssertionConsumerService(this.token(17, null, null),
        "AssertionConsumerService given in AuthnRequest does not appear in metadata");
  }

  @Test
  public void testUrlOnly() {
    final Saml2AuthnRequestAuthenticationToken token = this.token(null, ACS_0, null);

    this.validator.validate(token);

    Assertions.assertEquals(ACS_0, token.getAssertionConsumerServiceUrl());
  }

  @Test
  public void testUrlNotInMetadata() {
    this.assertInvalidAssertionConsumerService(this.token(null, "https://sp.example.com/other", null),
        "AssertionConsumerService given in AuthnRequest does not appear in metadata");
  }

  @Test
  public void testUrlAndBinding() {
    final Saml2AuthnRequestAuthenticationToken token =
        this.token(null, ACS_0, SAMLConstants.SAML2_POST_BINDING_URI);

    this.validator.validate(token);

    Assertions.assertEquals(ACS_0, token.getAssertionConsumerServiceUrl());
  }

  @Test
  public void testBindingOnly() {
    final Saml2AuthnRequestAuthenticationToken token = this.token(null, null, SAMLConstants.SAML2_POST_BINDING_URI);

    this.validator.validate(token);

    Assertions.assertEquals(ACS_1, token.getAssertionConsumerServiceUrl());
  }

  @Test
  public void testNoAssertionConsumerServiceInformation() {
    final Saml2AuthnRequestAuthenticationToken token = this.token(null, null, null);

    this.validator.validate(token);

    Assertions.assertEquals(ACS_1, token.getAssertionConsumerServiceUrl());
  }

  @Test
  public void testNoAssertionConsumerServiceInformationAndNoDefaultInMetadata() {
    final EntityDescriptor metadata = EntityDescriptorBuilder.builder()
        .entityID(SP_ENTITY_ID)
        .roleDescriptors(SPSSODescriptorBuilder.builder().build())
        .build();

    this.assertInvalidAssertionConsumerService(this.token(null, null, null, metadata),
        "No AssertionConsumerService given in AuthnRequest"
            + " and no valid AssertionConsumerService found in metadata");
  }

  @Test
  public void testIndexAndUrl() {
    this.assertInvalidAssertionConsumerService(this.token(2, ACS_0, null),
        "AssertionConsumerServiceIndex in AuthnRequest must not be combined with AssertionConsumerServiceURL");
  }

  /**
   * The index and the URL pointing to the same entry is rejected as well.
   */
  @Test
  public void testIndexAndUrlForSameEntry() {
    this.assertInvalidAssertionConsumerService(this.token(0, ACS_0, null),
        "AssertionConsumerServiceIndex in AuthnRequest must not be combined with AssertionConsumerServiceURL");
  }

  @Test
  public void testIndexAndBinding() {
    this.assertInvalidAssertionConsumerService(this.token(0, null, SAMLConstants.SAML2_POST_BINDING_URI),
        "AssertionConsumerServiceIndex in AuthnRequest must not be combined with ProtocolBinding");
  }

  @Test
  public void testIndexAndUrlAndBinding() {
    this.assertInvalidAssertionConsumerService(this.token(0, ACS_0, SAMLConstants.SAML2_POST_BINDING_URI),
        "AssertionConsumerServiceIndex in AuthnRequest must not be combined with "
            + "AssertionConsumerServiceURL and ProtocolBinding");
  }

  /**
   * An index that does not appear in metadata is rejected for being combined with a URL, i.e. the combination is
   * checked before the contents of the metadata.
   */
  @Test
  public void testUnknownIndexAndUrl() {
    this.assertInvalidAssertionConsumerService(this.token(17, ACS_0, null),
        "AssertionConsumerServiceIndex in AuthnRequest must not be combined with AssertionConsumerServiceURL");
  }

  /**
   * A custom URI comparator is used when matching the URL.
   */
  @Test
  public void testCustomUriComparator() {
    this.validator.setUriComparator((uri1, uri2) -> true);

    final Saml2AuthnRequestAuthenticationToken token = this.token(null, "https://sp.example.com/no-match", null);

    this.validator.validate(token);

    Assertions.assertEquals(ACS_0, token.getAssertionConsumerServiceUrl());
  }

  /**
   * Asserts that validation of the given token is rejected with {@link
   * UnrecoverableSaml2IdpError#INVALID_ASSERTION_CONSUMER_SERVICE} and the given message.
   *
   * @param token the token to validate
   * @param message the expected message
   */
  private void assertInvalidAssertionConsumerService(final Saml2AuthnRequestAuthenticationToken token,
      final String message) {
    final UnrecoverableSaml2IdpException exception =
        Assertions.assertThrows(UnrecoverableSaml2IdpException.class, () -> this.validator.validate(token));

    Assertions.assertEquals(UnrecoverableSaml2IdpError.INVALID_ASSERTION_CONSUMER_SERVICE, exception.getError());
    Assertions.assertTrue(exception.getMessage().contains(message),
        "Expected message to contain '%s', but was: %s".formatted(message, exception.getMessage()));
    Assertions.assertNull(token.getAssertionConsumerServiceUrl());
  }

  /**
   * Creates a token for an {@code AuthnRequest} with the given AssertionConsumerService information, and with SP
   * metadata holding three AssertionConsumerService entries.
   *
   * @param index the {@code AssertionConsumerServiceIndex}, or null
   * @param url the {@code AssertionConsumerServiceURL}, or null
   * @param binding the {@code ProtocolBinding}, or null
   * @return a {@link Saml2AuthnRequestAuthenticationToken}
   */
  private Saml2AuthnRequestAuthenticationToken token(final Integer index, final String url, final String binding) {
    return this.token(index, url, binding, this.metadata());
  }

  /**
   * Creates a token for an {@code AuthnRequest} with the given AssertionConsumerService information.
   *
   * @param index the {@code AssertionConsumerServiceIndex}, or null
   * @param url the {@code AssertionConsumerServiceURL}, or null
   * @param binding the {@code ProtocolBinding}, or null
   * @param metadata the SP metadata
   * @return a {@link Saml2AuthnRequestAuthenticationToken}
   */
  private Saml2AuthnRequestAuthenticationToken token(final Integer index, final String url, final String binding,
      final EntityDescriptor metadata) {

    final AuthnRequest authnRequest =
        (AuthnRequest) XMLObjectSupport.buildXMLObject(AuthnRequest.DEFAULT_ELEMENT_NAME);
    authnRequest.setID("_authn-request-id");
    authnRequest.setAssertionConsumerServiceIndex(index);
    authnRequest.setAssertionConsumerServiceURL(url);
    authnRequest.setProtocolBinding(binding);

    final Saml2AuthnRequestAuthenticationToken token =
        new Saml2AuthnRequestAuthenticationToken(authnRequest, "the-relay-state");
    token.setPeerMetadata(metadata);
    return token;
  }

  /**
   * Creates SP metadata with three AssertionConsumerService entries, where the entry having index 1 is the default.
   *
   * @return an {@link EntityDescriptor}
   */
  private EntityDescriptor metadata() {
    return EntityDescriptorBuilder.builder()
        .entityID(SP_ENTITY_ID)
        .roleDescriptors(SPSSODescriptorBuilder.builder()
            .assertionConsumerServices(
                AssertionConsumerServiceBuilder.builder()
                    .binding(SAMLConstants.SAML2_POST_BINDING_URI)
                    .location(ACS_0)
                    .index(0)
                    .build(),
                AssertionConsumerServiceBuilder.builder()
                    .binding(SAMLConstants.SAML2_POST_BINDING_URI)
                    .location(ACS_1)
                    .isDefault(true)
                    .index(1)
                    .build(),
                AssertionConsumerServiceBuilder.builder()
                    .binding(SAMLConstants.SAML2_REDIRECT_BINDING_URI)
                    .location(ACS_2)
                    .index(2)
                    .build())
            .build())
        .build();
  }

}
