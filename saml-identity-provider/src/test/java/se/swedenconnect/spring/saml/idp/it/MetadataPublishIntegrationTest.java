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
package se.swedenconnect.spring.saml.idp.it;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.ByteArrayInputStream;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.saml2.metadata.EncryptionMethod;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.Extensions;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.security.credential.UsageType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeConstants;
import se.swedenconnect.opensaml.sweid.saml2.authn.psc.RequestedPrincipalSelection;
import se.swedenconnect.opensaml.sweid.saml2.authn.psc.build.MatchValueBuilder;
import se.swedenconnect.opensaml.sweid.saml2.authn.psc.build.RequestedPrincipalSelectionBuilder;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.spring.saml.idp.OpenSamlTestBase;
import se.swedenconnect.spring.saml.idp.config.Saml2IdpConfiguration;
import se.swedenconnect.spring.saml.idp.config.configurers.Saml2IdpConfigurerAdapter;
import se.swedenconnect.spring.saml.idp.it.MetadataPublishIntegrationTest.ApplicationConfiguration;
import se.swedenconnect.spring.saml.idp.settings.CredentialSettings;
import se.swedenconnect.spring.saml.idp.settings.EndpointSettings;
import se.swedenconnect.spring.saml.idp.settings.IdentityProviderSettings;
import se.swedenconnect.spring.saml.idp.settings.MetadataSettings;
import se.swedenconnect.spring.saml.idp.settings.MetadataSettings.ContactPersonSettings;
import se.swedenconnect.spring.saml.idp.settings.MetadataSettings.ContactPersonType;
import se.swedenconnect.spring.saml.idp.settings.MetadataSettings.OrganizationSettings;

/**
 * Test case for downloading IdP's metadata.
 *
 * @author Martin Lindström
 */
@SpringBootTest
@ContextConfiguration(classes = { ApplicationConfiguration.class })
@WebAppConfiguration
@AutoConfigureMockMvc
public class MetadataPublishIntegrationTest extends OpenSamlTestBase {

  private MockMvc mvc;

  @Autowired
  private WebApplicationContext webApplicationContext;

  @BeforeEach
  public void setup() throws Exception {
    this.mvc = MockMvcBuilders.webAppContextSetup(this.webApplicationContext)
        .apply(springSecurity())
        .build();
  }

  @Test
  public void testDownload() throws Exception {

    final MvcResult result = this.mvc.perform(
        MockMvcRequestBuilders.get(EndpointSettings.SAML_METADATA_PUBLISH_ENDPOINT_DEFAULT))
        // .andDo(MockMvcResultHandlers.print())
        .andExpect(status().isOk())
        .andReturn();

    final EntityDescriptor metadata = unmarshall(
        new ByteArrayInputStream(result.getResponse().getContentAsByteArray()), EntityDescriptor.class);

    Assertions.assertNotNull(metadata);
    Assertions.assertEquals(TestSupport.IDP_ENTITY_ID, metadata.getEntityID());
    Assertions.assertNotNull(metadata.getCacheDuration());
    Assertions.assertNotNull(metadata.getID());
    final String id = metadata.getID();

    // Do it again - verify that we get cached metadata
    //
    final MediaType xmlType = new MediaType("application", "samlmetadata+xml");
    final MvcResult result2 = this.mvc.perform(
        MockMvcRequestBuilders
            .get(EndpointSettings.SAML_METADATA_PUBLISH_ENDPOINT_DEFAULT)
            .accept(xmlType))
        .andExpect(status().isOk())
        .andExpect(MockMvcResultMatchers.content().contentType(xmlType))
        .andReturn();

    final EntityDescriptor metadata2 = unmarshall(
        new ByteArrayInputStream(result2.getResponse().getContentAsByteArray()), EntityDescriptor.class);

    Assertions.assertEquals(id, metadata2.getID());
  }

  @Configuration
  @Import({ CredentialConfiguration.class, Saml2IdpConfiguration.class })
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

    @MockBean
    MetadataResolver metadataResolver;

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

    @Bean
    Saml2IdpConfigurerAdapter idpConfigurerAdapter() {
      return (http, configurer) -> {
        configurer.idpMetadataEndpoint(mdCustomizer -> {
          mdCustomizer.entityDescriptorCustomizer(this.metadataCustomizer());
        });
      };
    }

    // For customizing the metadata published by the IdP
    //
    private Customizer<EntityDescriptor> metadataCustomizer() {
      return e -> {
        final RequestedPrincipalSelection rps = RequestedPrincipalSelectionBuilder.builder()
            .matchValues(MatchValueBuilder.builder()
                .name(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER)
                .build())
            .build();

        final IDPSSODescriptor ssoDescriptor = e.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);
        Extensions extensions = ssoDescriptor.getExtensions();
        if (extensions == null) {
          extensions = (Extensions) XMLObjectSupport.buildXMLObject(Extensions.DEFAULT_ELEMENT_NAME);
          ssoDescriptor.setExtensions(extensions);
        }
        extensions.getUnknownXMLObjects().add(rps);

        KeyDescriptor encryption = null;
        for (final KeyDescriptor kd : ssoDescriptor.getKeyDescriptors()) {
          if (UsageType.ENCRYPTION == kd.getUse()) {
            encryption = kd;
            break;
          }
          if (kd.getUse() == null || UsageType.UNSPECIFIED == kd.getUse()) {
            encryption = kd;
          }
        }
        if (encryption != null) {
          final String[] algs = { "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
              "http://www.w3.org/2009/xmlenc11#aes256-gcm",
              "http://www.w3.org/2009/xmlenc11#aes192-gcm",
              "http://www.w3.org/2009/xmlenc11#aes128-gcm"
          };
          for (final String alg : algs) {
            final EncryptionMethod method =
                (EncryptionMethod) XMLObjectSupport.buildXMLObject(EncryptionMethod.DEFAULT_ELEMENT_NAME);
            method.setAlgorithm(alg);
            encryption.getEncryptionMethods().add(method);
          }
        }

      };
    }

  }

}
