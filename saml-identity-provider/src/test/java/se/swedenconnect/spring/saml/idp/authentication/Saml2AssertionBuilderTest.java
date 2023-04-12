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
package se.swedenconnect.spring.saml.idp.authentication;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.config.Customizer;

import lombok.Getter;
import se.swedenconnect.opensaml.saml2.metadata.build.SPSSODescriptorBuilder;
import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeConstants;
import se.swedenconnect.opensaml.sweid.saml2.authn.LevelOfAssuranceUris;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.factory.PkiCredentialFactoryBean;
import se.swedenconnect.spring.saml.idp.OpenSamlTestBase;
import se.swedenconnect.spring.saml.idp.attributes.UserAttribute;
import se.swedenconnect.spring.saml.idp.attributes.nameid.PersistentNameIDGenerator;
import se.swedenconnect.spring.saml.idp.attributes.release.AttributeReleaseManager;
import se.swedenconnect.spring.saml.idp.attributes.release.DefaultAttributeReleaseManager;
import se.swedenconnect.spring.saml.idp.attributes.release.ReleaseAllAttributeProducer;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpException;
import se.swedenconnect.spring.saml.idp.settings.AssertionSettings;
import se.swedenconnect.spring.saml.idp.utils.DefaultSaml2MessageIDGenerator;

/**
 * Test cases for Saml2AssertionBuilder.
 * 
 * @author Martin Lindström
 */
public class Saml2AssertionBuilderTest extends OpenSamlTestBase {

  private static PkiCredential credential;

  private static final String IDP = "https://idp.example.com";
  private static final String SP = "https://sp.example.com";

  private static final String AUTHNREQUEST_ID = "_ID-ABC123";
  private static final String ASSERTION_CONSUMER_SERVICE_URL = SP + "/sso";

  @BeforeAll
  public static void init() throws Exception {
    final PkiCredentialFactoryBean factory = new PkiCredentialFactoryBean();
    factory.setResource(new ClassPathResource("idp-credentials.jks"));
    factory.setAlias("sign");
    factory.setType("JKS");
    factory.setPassword("secret".toCharArray());
    factory.afterPropertiesSet();
    credential = factory.getObject();
  }
  
  @Test
  public void testBuild() throws Exception {

    final AttributeReleaseManager releaseManager =
        new DefaultAttributeReleaseManager(List.of(new ReleaseAllAttributeProducer()), null);

    final TestCustomizer customizer = new TestCustomizer(); 
    
    final Saml2AssertionBuilder builder = new Saml2AssertionBuilder(IDP, credential, releaseManager);
    builder.setAssertionCustomizer(customizer);

    final Saml2AuthnRequestAuthenticationToken authnRequestToken =
        Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(authnRequestToken.getLogString()).thenReturn("logstring");
    Mockito.when(authnRequestToken.getNameIDGenerator()).thenReturn(new PersistentNameIDGenerator(IDP, SP));

    final AuthnRequest authnRequest = (AuthnRequest) XMLObjectSupport.buildXMLObject(AuthnRequest.DEFAULT_ELEMENT_NAME);
    authnRequest.setID(AUTHNREQUEST_ID);
    Mockito.when(authnRequestToken.getAuthnRequest()).thenReturn(authnRequest);

    final EntityDescriptor entityDescriptor =
        (EntityDescriptor) XMLObjectSupport.buildXMLObject(EntityDescriptor.DEFAULT_ELEMENT_NAME);
    entityDescriptor.setEntityID(SP);
    entityDescriptor.getRoleDescriptors().add(
        SPSSODescriptorBuilder.builder().wantAssertionsSigned(true).build());

    Mockito.when(authnRequestToken.getPeerMetadata()).thenReturn(entityDescriptor);

    Mockito.when(authnRequestToken.getAssertionConsumerServiceUrl()).thenReturn(ASSERTION_CONSUMER_SERVICE_URL);

    final Saml2UserDetails userDetails = new Saml2UserDetails(List.of(
        new UserAttribute(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER,
            AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_PERSONAL_IDENTITY_NUMBER,
            "197705232382"),
        new UserAttribute(AttributeConstants.ATTRIBUTE_NAME_DISPLAY_NAME,
            AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_DISPLAY_NAME,
            "Frida Kransstege")),
        AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER, LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3,
        Instant.now().minusSeconds(10), "235.87.12.4");

    final Saml2UserAuthentication token = new Saml2UserAuthentication(userDetails);
    token.setAuthnRequestToken(authnRequestToken);

    final Assertion assertion = builder.buildAssertion(token);

    Assertions.assertTrue(assertion.isSigned());
    Assertions.assertEquals(IDP, assertion.getIssuer().getValue());
    Assertions.assertEquals(SP, assertion.getSubject().getNameID().getSPNameQualifier());
    Assertions.assertEquals(AUTHNREQUEST_ID,
        assertion.getSubject().getSubjectConfirmations().get(0).getSubjectConfirmationData().getInResponseTo());
    Assertions.assertEquals(SP,
        assertion.getConditions().getAudienceRestrictions().get(0).getAudiences().get(0).getURI());
    Assertions.assertEquals(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3,
        assertion.getAuthnStatements().get(0).getAuthnContext().getAuthnContextClassRef().getURI());
    Assertions.assertTrue(assertion.getAttributeStatements().get(0).getAttributes().size() == 2);
    Assertions.assertTrue(customizer.isCalled());
  }
  
  private static class TestCustomizer implements Customizer<Assertion> {
    
    @Getter
    private boolean called = false;

    @Override
    public void customize(final Assertion t) {
      this.called = true;
    }
    
  }
  
  @Test
  public void testBuildNotSignedAndAuthenticatingAuth() throws Exception {

    final AttributeReleaseManager releaseManager =
        new DefaultAttributeReleaseManager(List.of(new ReleaseAllAttributeProducer()), null);

    final Saml2AssertionBuilder builder = new Saml2AssertionBuilder(IDP, credential, releaseManager);
    builder.setIdGenerator(new DefaultSaml2MessageIDGenerator());
    builder.setNotBeforeDuration(AssertionSettings.NOT_BEFORE_DURATION_DEFAULT);
    builder.setNotOnOrAfterDuration(AssertionSettings.NOT_ON_OR_AFTER_DURATION_DEFAULT);

    final Saml2AuthnRequestAuthenticationToken authnRequestToken =
        Mockito.mock(Saml2AuthnRequestAuthenticationToken.class);
    Mockito.when(authnRequestToken.getLogString()).thenReturn("logstring");
    Mockito.when(authnRequestToken.getNameIDGenerator()).thenReturn(new PersistentNameIDGenerator(IDP, SP));

    final AuthnRequest authnRequest = (AuthnRequest) XMLObjectSupport.buildXMLObject(AuthnRequest.DEFAULT_ELEMENT_NAME);
    authnRequest.setID(AUTHNREQUEST_ID);
    Mockito.when(authnRequestToken.getAuthnRequest()).thenReturn(authnRequest);

    final EntityDescriptor entityDescriptor =
        (EntityDescriptor) XMLObjectSupport.buildXMLObject(EntityDescriptor.DEFAULT_ELEMENT_NAME);
    entityDescriptor.setEntityID(SP);
    entityDescriptor.getRoleDescriptors().add(
        SPSSODescriptorBuilder.builder().wantAssertionsSigned(false).build());

    Mockito.when(authnRequestToken.getPeerMetadata()).thenReturn(entityDescriptor);

    Mockito.when(authnRequestToken.getAssertionConsumerServiceUrl()).thenReturn(ASSERTION_CONSUMER_SERVICE_URL);

    final Saml2UserDetails userDetails = new Saml2UserDetails(List.of(
        new UserAttribute(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER,
            AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_PERSONAL_IDENTITY_NUMBER,
            "197705232382"),
        new UserAttribute(AttributeConstants.ATTRIBUTE_NAME_DISPLAY_NAME,
            AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_DISPLAY_NAME,
            "Frida Kransstege")),
        AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER, LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3,
        Instant.now().minusSeconds(10), "235.87.12.4");
    userDetails.setAuthenticatingAuthority("https://otheridp.example.com");

    final Saml2UserAuthentication token = new Saml2UserAuthentication(userDetails);
    token.setAuthnRequestToken(authnRequestToken);

    final Assertion assertion = builder.buildAssertion(token);

    Assertions.assertFalse(assertion.isSigned());
    Assertions.assertEquals(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3,
        assertion.getAuthnStatements().get(0).getAuthnContext().getAuthnContextClassRef().getURI());
    Assertions.assertEquals("https://otheridp.example.com", 
        assertion.getAuthnStatements().get(0).getAuthnContext().getAuthenticatingAuthorities().get(0).getURI());
    Assertions.assertTrue(assertion.getAttributeStatements().get(0).getAttributes().size() == 2);    
  }

  @Test
  public void testMissingAuthnRequestToken() {
    final AttributeReleaseManager releaseManager =
        new DefaultAttributeReleaseManager(List.of(new ReleaseAllAttributeProducer()), null);

    final Saml2AssertionBuilder builder = new Saml2AssertionBuilder(IDP, credential, releaseManager);
    
    final Saml2UserAuthentication token = Mockito.mock(Saml2UserAuthentication.class);
    Mockito.when(token.getAuthnRequestToken()).thenReturn(null);
    
    Assertions.assertThrows(UnrecoverableSaml2IdpException.class, () -> {
      builder.buildAssertion(token);
    });
    
  }

}
