/*
 * Copyright 2023-2024 Sweden Connect
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
package se.swedenconnect.spring.saml.idp.it;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.ByteArrayInputStream;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.saml2.core.Extensions;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.actuate.audit.listener.AuditApplicationEvent;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.RequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultHandlers;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import lombok.Getter;
import se.swedenconnect.opensaml.saml2.request.AuthnRequestGenerator;
import se.swedenconnect.opensaml.saml2.request.AuthnRequestGeneratorContext;
import se.swedenconnect.opensaml.saml2.response.ResponseProcessingResult;
import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeConstants;
import se.swedenconnect.opensaml.sweid.saml2.authn.LevelOfAssuranceUris;
import se.swedenconnect.opensaml.sweid.saml2.metadata.entitycategory.EntityCategoryConstants;
import se.swedenconnect.opensaml.sweid.saml2.request.SwedishEidAuthnRequestGeneratorContext;
import se.swedenconnect.opensaml.sweid.saml2.signservice.dss.Message;
import se.swedenconnect.opensaml.sweid.saml2.signservice.dss.SignMessage;
import se.swedenconnect.opensaml.sweid.saml2.signservice.dss.SignMessageMimeTypeEnum;
import se.swedenconnect.opensaml.sweid.saml2.signservice.sap.SADRequest;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.spring.saml.idp.OpenSamlTestBase;
import se.swedenconnect.spring.saml.idp.attributes.UserAttribute;
import se.swedenconnect.spring.saml.idp.audit.Saml2AuditEvent;
import se.swedenconnect.spring.saml.idp.audit.Saml2AuditEvents;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthentication;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthenticationInputToken;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserDetails;
import se.swedenconnect.spring.saml.idp.authentication.provider.AbstractUserAuthenticationProvider;
import se.swedenconnect.spring.saml.idp.config.Saml2IdpConfiguration;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;
import se.swedenconnect.spring.saml.idp.events.AbstractSaml2IdpEvent;
import se.swedenconnect.spring.saml.idp.events.AbstractSaml2IdpEventListener;
import se.swedenconnect.spring.saml.idp.events.Saml2AuthnRequestReceivedEvent;
import se.swedenconnect.spring.saml.idp.events.Saml2PostUserAuthenticationEvent;
import se.swedenconnect.spring.saml.idp.events.Saml2PreUserAuthenticationEvent;
import se.swedenconnect.spring.saml.idp.events.Saml2SuccessResponseEvent;
import se.swedenconnect.spring.saml.idp.it.AuthenticationIntegrationTest.ApplicationConfiguration;
import se.swedenconnect.spring.saml.idp.settings.CredentialSettings;
import se.swedenconnect.spring.saml.idp.settings.EndpointSettings;
import se.swedenconnect.spring.saml.idp.settings.IdentityProviderSettings;
import se.swedenconnect.spring.saml.idp.settings.MetadataSettings;
import se.swedenconnect.spring.saml.idp.settings.MetadataSettings.ContactPersonSettings;
import se.swedenconnect.spring.saml.idp.settings.MetadataSettings.ContactPersonType;
import se.swedenconnect.spring.saml.idp.settings.MetadataSettings.OrganizationSettings;

@SpringBootTest(properties = { "management.auditevents.enabled=true" })
@ContextConfiguration(classes = { ApplicationConfiguration.class })
@WebAppConfiguration
@AutoConfigureMockMvc
public class AuthenticationIntegrationTest extends OpenSamlTestBase {

  private MockMvc mvc;

  @Autowired
  private WebApplicationContext webApplicationContext;

  @Autowired
  private Saml2EventListener eventListener;

  @Autowired
  private AuditEventListener auditListener;

  @MockBean
  MetadataResolver metadataResolver;

  MetadataResolver simulatedResolver;

  @BeforeEach
  public void setup() throws Exception {
    this.mvc = MockMvcBuilders.webAppContextSetup(this.webApplicationContext)
        .apply(springSecurity())
        .build();

    Mockito.when(metadataResolver.resolveSingle(Mockito.any())).thenAnswer(a -> {
      return this.simulatedResolver.resolveSingle(a.getArgument(0));
    });
    Mockito.when(metadataResolver.resolve(Mockito.any())).thenAnswer(a -> {
      return this.simulatedResolver.resolve(a.getArgument(0));
    });

    this.eventListener.clear();
    this.auditListener.clear();
  }

  @Test
  public void authenticatePost() throws Exception {
    final TestSp testSp = new TestSp();
    testSp.setWantsAssertionsSigned(true);
    testSp.setEntityCategories(List.of(EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA3_NAME.getUri()));

    final EntityDescriptor spMetadata = testSp.getSpMetadata();
    final EntityDescriptor idpMetadata = this.getIdpMetadata();
    this.simulatedResolver = TestSupport.createMetadataResolver(spMetadata, idpMetadata);

    testSp.setupResponseProcessor(this.simulatedResolver);

    final AuthnRequestGenerator generator = testSp.createAuthnRequestGenerator(idpMetadata);

    final AuthnRequestGeneratorContext context = new AuthnRequestGeneratorContext() {

      @Override
      public String getPreferredBinding() {
        return SAMLConstants.SAML2_POST_BINDING_URI;
      }

    };

    final RequestBuilder requestBuilder =
        testSp.generateRequest(TestSupport.IDP_ENTITY_ID, generator, context, "relay-state", null);

    final MvcResult result = mvc.perform(requestBuilder)
        .andDo(MockMvcResultHandlers.print())
        .andExpect(status().isOk())
        .andReturn();

    final ResponseProcessingResult processingResult = testSp.processSamlResponse(result);
    Assertions.assertNotNull(processingResult);

    Assertions.assertTrue(this.eventListener.getEvents().size() == 4);
    Assertions.assertTrue(this.eventListener.getEvents().get(0) instanceof Saml2AuthnRequestReceivedEvent);
    Assertions.assertTrue(this.eventListener.getEvents().get(1) instanceof Saml2PreUserAuthenticationEvent);
    Assertions.assertTrue(this.eventListener.getEvents().get(2) instanceof Saml2PostUserAuthenticationEvent);
    Assertions.assertTrue(this.eventListener.getEvents().get(3) instanceof Saml2SuccessResponseEvent);

    // Auditing
    Assertions.assertEquals(4, this.auditListener.getEvents().size());
    Assertions.assertEquals(Saml2AuditEvents.SAML2_AUDIT_REQUEST_RECEIVED.getTypeName(), this.auditListener.getEvents().get(0).getType());
    Assertions.assertEquals(Saml2AuditEvents.SAML2_AUDIT_BEFORE_USER_AUTHN.getTypeName(), this.auditListener.getEvents().get(1).getType());
    Assertions.assertEquals(Saml2AuditEvents.SAML2_AUDIT_AFTER_USER_AUTHN.getTypeName(), this.auditListener.getEvents().get(2).getType());
    Assertions.assertEquals(Saml2AuditEvents.SAML2_AUDIT_SUCCESSFUL_RESPONSE.getTypeName(), this.auditListener.getEvents().get(3).getType());
  }

  @Test
  public void authenticateSignService() throws Exception {
    final TestSp testSp = new TestSp();
    testSp.setWantsAssertionsSigned(true);
    testSp.setEntityCategories(List.of(EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA3_NAME.getUri(),
        EntityCategoryConstants.SERVICE_TYPE_CATEGORY_SIGSERVICE.getUri()));

    final EntityDescriptor spMetadata = testSp.getSpMetadata();
    final EntityDescriptor idpMetadata = this.getIdpMetadata();
    this.simulatedResolver = TestSupport.createMetadataResolver(spMetadata, idpMetadata);

    testSp.setupResponseProcessor(this.simulatedResolver);

    final AuthnRequestGenerator generator = testSp.createAuthnRequestGenerator(idpMetadata);

    final AuthnRequestGeneratorContext context = new SwedishEidAuthnRequestGeneratorContext() {

      @Override
      public String getPreferredBinding() {
        return SAMLConstants.SAML2_POST_BINDING_URI;
      }

      @Override
      public SignMessageBuilderFunction getSignMessageBuilderFunction() {
        return (metadata, signMessageEncrypter) -> {
          final SignMessage signMessage =
              (SignMessage) XMLObjectSupport.buildXMLObject(SignMessage.DEFAULT_ELEMENT_NAME);
          signMessage.setDisplayEntity(TestSupport.IDP_ENTITY_ID);
          signMessage.setMimeType(SignMessageMimeTypeEnum.TEXT);
          signMessage.setMustShow(true);
          final Message msg = (Message) XMLObjectSupport.buildXMLObject(Message.DEFAULT_ELEMENT_NAME);
          msg.setContent("This is a sign message");
          signMessage.setMessage(msg);
          if (signMessageEncrypter != null) {
            try {
              signMessageEncrypter.encrypt(signMessage, TestSupport.IDP_ENTITY_ID);
            }
            catch (EncryptionException e) {
            }
          }
          return signMessage;
        };
      }

      @Override
      public AuthnRequestCustomizer getAuthnRequestCustomizer() {
        return (authnRequest) -> {
          final SADRequest sadRequest = (SADRequest) XMLObjectSupport.buildXMLObject(SADRequest.DEFAULT_ELEMENT_NAME);
          sadRequest.setID("ABCDEF");
          sadRequest.setDocCount(4);
          sadRequest.setRequesterID(TestSp.ENTITY_ID);
          sadRequest.setSignRequestID("123456789");
          if (authnRequest.getExtensions() == null) {
            final Extensions extensions = (Extensions) XMLObjectSupport.buildXMLObject(Extensions.DEFAULT_ELEMENT_NAME);
            authnRequest.setExtensions(extensions);
          }
          authnRequest.getExtensions().getUnknownXMLObjects().add(sadRequest);
        };
      }

    };

    final RequestBuilder requestBuilder =
        testSp.generateRequest(TestSupport.IDP_ENTITY_ID, generator, context, "relay-state", null);

    final MvcResult result = mvc.perform(requestBuilder)
        .andDo(MockMvcResultHandlers.print())
        .andExpect(status().isOk())
        .andReturn();

    final ResponseProcessingResult processingResult = testSp.processSamlResponse(result);
    Assertions.assertNotNull(processingResult);

    Assertions.assertTrue(processingResult.getAttributes().stream()
        .filter(a -> AttributeConstants.ATTRIBUTE_NAME_SIGNMESSAGE_DIGEST.equals(a.getName()))
        .findFirst()
        .isPresent());
    Assertions.assertTrue(processingResult.getAttributes().stream()
        .filter(a -> AttributeConstants.ATTRIBUTE_NAME_SAD.equals(a.getName()))
        .findFirst()
        .isPresent());

    Assertions.assertTrue(this.eventListener.getEvents().size() == 4);
    Assertions.assertTrue(this.eventListener.getEvents().get(0) instanceof Saml2AuthnRequestReceivedEvent);
    Assertions.assertTrue(this.eventListener.getEvents().get(1) instanceof Saml2PreUserAuthenticationEvent);
    Assertions.assertTrue(this.eventListener.getEvents().get(2) instanceof Saml2PostUserAuthenticationEvent);
    Assertions.assertTrue(this.eventListener.getEvents().get(3) instanceof Saml2SuccessResponseEvent);

    // Auditing
    Assertions.assertEquals(4, this.auditListener.getEvents().size());
  }

  @Test
  public void authenticateSso() throws Exception {
    final TestSp testSp = new TestSp();
    testSp.setWantsAssertionsSigned(true);
    testSp.setEntityCategories(List.of(EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA3_NAME.getUri()));

    final EntityDescriptor spMetadata = testSp.getSpMetadata();
    final EntityDescriptor idpMetadata = this.getIdpMetadata();
    this.simulatedResolver = TestSupport.createMetadataResolver(spMetadata, idpMetadata);

    testSp.setupResponseProcessor(this.simulatedResolver);

    final AuthnRequestGenerator generator = testSp.createAuthnRequestGenerator(idpMetadata);

    AuthnRequestGeneratorContext context = new AuthnRequestGeneratorContext() {

      @Override
      public String getPreferredBinding() {
        return SAMLConstants.SAML2_POST_BINDING_URI;
      }
    };

    final RequestBuilder requestBuilder =
        testSp.generateRequest(TestSupport.IDP_ENTITY_ID, generator, context, "relay-state", null);

    final MvcResult result = mvc.perform(requestBuilder)
        .andDo(MockMvcResultHandlers.print())
        .andExpect(status().isOk())
        .andReturn();

    final MockHttpSession session = (MockHttpSession) result.getRequest().getSession();

    final ResponseProcessingResult processingResult = testSp.processSamlResponse(result);
    Assertions.assertNotNull(processingResult);
    final Instant authnInstant = processingResult.getAuthnInstant();

    Assertions.assertTrue(this.eventListener.getEvents().size() == 4);
    Assertions.assertTrue(this.eventListener.getEvents().get(0) instanceof Saml2AuthnRequestReceivedEvent);
    Assertions.assertTrue(this.eventListener.getEvents().get(1) instanceof Saml2PreUserAuthenticationEvent);
    Assertions.assertTrue(this.eventListener.getEvents().get(2) instanceof Saml2PostUserAuthenticationEvent);
    Assertions.assertFalse(Saml2PostUserAuthenticationEvent.class.cast(this.eventListener.getEvents().get(2))
        .getUserAuthentication().isSsoApplied());
    Assertions.assertTrue(this.eventListener.getEvents().get(3) instanceof Saml2SuccessResponseEvent);

    // Authenticate again
    //
    context = new AuthnRequestGeneratorContext() {

      @Override
      public Boolean getForceAuthnAttribute() {
        return false;
      }

      @Override
      public Boolean getIsPassiveAttribute() {
        return true;
      }

      @Override
      public String getPreferredBinding() {
        return SAMLConstants.SAML2_POST_BINDING_URI;
      }
    };

    final RequestBuilder requestBuilder2 =
        testSp.generateRequest(TestSupport.IDP_ENTITY_ID, generator, context, "relay-state", session);

    final MvcResult result2 = mvc.perform(requestBuilder2)
        .andDo(MockMvcResultHandlers.print())
        .andExpect(status().isOk())
        .andReturn();

    final ResponseProcessingResult processingResult2 = testSp.processSamlResponse(result2);
    Assertions.assertNotNull(processingResult2);
    Assertions.assertEquals(authnInstant, processingResult2.getAuthnInstant());

    Assertions.assertTrue(this.eventListener.getEvents().size() == 8);
    Assertions.assertTrue(this.eventListener.getEvents().get(4) instanceof Saml2AuthnRequestReceivedEvent);
    Assertions.assertTrue(this.eventListener.getEvents().get(5) instanceof Saml2PreUserAuthenticationEvent);
    Assertions.assertTrue(this.eventListener.getEvents().get(6) instanceof Saml2PostUserAuthenticationEvent);
    Assertions.assertTrue(Saml2PostUserAuthenticationEvent.class.cast(this.eventListener.getEvents().get(6))
        .getUserAuthentication().isSsoApplied());
    Assertions.assertTrue(this.eventListener.getEvents().get(7) instanceof Saml2SuccessResponseEvent);

    // Auditing
    Assertions.assertEquals(8, this.auditListener.getEvents().size());
  }

  private EntityDescriptor getIdpMetadata() throws Exception {
    final MvcResult result = mvc.perform(
        MockMvcRequestBuilders.get(EndpointSettings.SAML_METADATA_PUBLISH_ENDPOINT_DEFAULT))
        .andExpect(status().isOk())
        .andReturn();

    return unmarshall(
        new ByteArrayInputStream(result.getResponse().getContentAsByteArray()), EntityDescriptor.class);
  }

  @Component
  public static class TestAuthenticator extends AbstractUserAuthenticationProvider {

    @Override
    public String getName() {
      return "test";
    }

    @Override
    public List<String> getSupportedAuthnContextUris() {
      return List.of(LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3);
    }

    @Override
    public List<String> getEntityCategories() {
      return List.of(EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA3_PNR.getUri(),
          EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA3_NAME.getUri());
    }

    @Override
    protected Authentication authenticate(final Saml2UserAuthenticationInputToken token,
        final List<String> authnContextUris)
        throws Saml2ErrorStatusException {

      final Saml2UserDetails details = new Saml2UserDetails(List.of(
          new UserAttribute(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER,
              AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_PERSONAL_IDENTITY_NUMBER,
              "197309069289"),
          new UserAttribute(AttributeConstants.ATTRIBUTE_NAME_GIVEN_NAME,
              AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_GIVEN_NAME,
              "Nina"),
          new UserAttribute(AttributeConstants.ATTRIBUTE_NAME_SN,
              AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_SN,
              "Greger"),
          new UserAttribute(AttributeConstants.ATTRIBUTE_NAME_DISPLAY_NAME,
              AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_DISPLAY_NAME,
              "Nina Greger"),
          new UserAttribute(AttributeConstants.ATTRIBUTE_NAME_DATE_OF_BIRTH,
              AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_DATE_OF_BIRTH,
              "1973-09-06")),
          AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER,
          LevelOfAssuranceUris.AUTHN_CONTEXT_URI_LOA3,
          Instant.now(),
          "127.0.0.1");

      if (token.getAuthnRequestToken().isSignatureServicePeer()) {
        if (Optional.ofNullable(token.getAuthnRequestToken().getAuthnRequest().getExtensions())
            .map(e -> e.getUnknownXMLObjects(SignMessage.DEFAULT_ELEMENT_NAME))
            .filter(l -> !l.isEmpty())
            .isPresent()) {
          details.setSignMessageDisplayed(true);
        }
      }

      return new Saml2UserAuthentication(details);
    }

  }

  @Configuration
  @Import({ CredentialConfiguration.class, TestAuthenticator.class, Saml2IdpConfiguration.class })
  @EnableWebSecurity
  public static class ApplicationConfiguration {

    @Autowired
    @Qualifier("idp.credential.sign")
    PkiCredential signCredential;

    @Autowired
    @Qualifier("idp.credential.encrypt")
    PkiCredential encryptCredential;

    @Autowired
    @Qualifier("idp.credential.metadata")
    PkiCredential metadataCredential;

    @Autowired
    MetadataResolver metadataResolver;

    @Bean
    Saml2EventListener saml2EventListener() {
      return new Saml2EventListener();
    }

    @Bean
    AuditEventListener auditListener() {
      return new AuditEventListener();
    }

    @Bean
    IdentityProviderSettings identityProviderSettings() {

      final IdentityProviderSettings settings = IdentityProviderSettings.builder()
          .entityId(TestSupport.IDP_ENTITY_ID)
          .baseUrl(TestSupport.IDP_BASE_URL)
          .credentials(CredentialSettings.builder()
              .signCredential(this.signCredential)
              .encryptCredential(this.encryptCredential)
              .metadataSignCredential(this.metadataCredential)
              .build())
          .metadata(MetadataSettings.builder()
              .cacheDuration(MetadataSettings.SAML_METADATA_CACHE_DURATION_DEFAULT)
              .validityPeriod(MetadataSettings.SAML_METADATA_VALIDITY_DEFAULT)
              .contactPersons(Map.of(
                  ContactPersonType.support, ContactPersonSettings.builder()
                      .company("Sweden Connect")
                      .emailAddresses(List.of("operations@swedenconnect.se"))
                      .build(),
                  ContactPersonType.technical, ContactPersonSettings.builder()
                      .company("Sweden Connect")
                      .emailAddresses(List.of("operations@swedenconnect.se"))
                      .build()))
              .organization(OrganizationSettings.builder()
                  .displayNames(Map.of(
                      "en", "Test Identity Provider",
                      "sv", "Legitimeringstjänst för test"))
                  .names(Map.of(
                      "en", "Sweden Connect",
                      "sv", "Sweden Connect"))
                  .build())
              .build())
          .metadataProvider(this.metadataResolver)
          .build();
      return settings;
    }

  }

  public static class Saml2EventListener extends AbstractSaml2IdpEventListener {

    @Getter
    private List<AbstractSaml2IdpEvent> events = new ArrayList<>();

    @Override
    public void onApplicationEvent(final AbstractSaml2IdpEvent event) {
      super.onApplicationEvent(event);
      this.events.add(event);
    }

    public void clear() {
      this.events.clear();
    }

  }

  public static class AuditEventListener implements ApplicationListener<AuditApplicationEvent> {

    @Getter
    private List<Saml2AuditEvent> events = new ArrayList<>();

    @Override
    public void onApplicationEvent(final AuditApplicationEvent event) {
      if (event.getAuditEvent() instanceof Saml2AuditEvent e) {
        events.add(e);
      }
    }

    public void clear() {
      this.events.clear();
    }

  }

}
