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
package se.swedenconnect.spring.saml.testsp.config;

import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.Extensions;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml5AuthenticationProvider;
import org.springframework.security.saml2.provider.service.metadata.OpenSaml5MetadataResolver;
import org.springframework.security.saml2.provider.service.metadata.OpenSaml5MetadataResolver.EntityDescriptorParameters;
import org.springframework.security.saml2.provider.service.metadata.Saml2MetadataResolver;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;
import org.springframework.security.saml2.provider.service.web.authentication.OpenSaml5AuthenticationRequestResolver;
import org.springframework.security.saml2.provider.service.web.authentication.OpenSaml5AuthenticationRequestResolver.AuthnRequestContext;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2AuthenticationRequestResolver;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import se.swedenconnect.opensaml.saml2.metadata.build.EntityAttributesBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.ExtensionsBuilder;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.bundle.CredentialBundles;
import se.swedenconnect.security.credential.config.ConfigurationResourceLoader;
import se.swedenconnect.security.credential.config.properties.PkiCredentialConfigurationProperties;
import se.swedenconnect.security.credential.factory.PkiCredentialFactory;
import se.swedenconnect.spring.saml.testsp.ext.ExtendedSaml2AuthenticationTokenConverter;
import se.swedenconnect.spring.saml.testsp.ext.ResponseAuthenticationConverter;

import java.util.Optional;
import java.util.function.Consumer;

/**
 * Configuration class for the Spring Security SAML SP.
 *
 * @author Martin Lindström
 */
@Configuration
public class SamlSpConfiguration {

  @Autowired
  ResponseAuthenticationConverter responseAuthenticationConverter;

  /** Credential bundles. */
  @Autowired
  CredentialBundles credentialBundles;

  /** Resource loader. */
  @Autowired
  private ConfigurationResourceLoader resourceLoader;

  @Bean
  RelyingPartyRegistrationResolver relyingPartyRegistrationResolver(
      final RelyingPartyRegistrationRepository registrations) {
    return new DefaultRelyingPartyRegistrationResolver(registrations);
  }

  @Bean
  Saml2MetadataResolver openSamlMetadataResolver(final SamlSpConfigurationProperties props) {
    final OpenSaml5MetadataResolver resolver = new OpenSaml5MetadataResolver();
    resolver.setEntityDescriptorCustomizer(metadataCustomizer(props));
    return resolver;
  }

  private static Consumer<EntityDescriptorParameters> metadataCustomizer(final SamlSpConfigurationProperties props) {

    return (pars) -> {
      final EntityDescriptor entityDescriptor = pars.getEntityDescriptor();

      final SPSSODescriptor sso = entityDescriptor.getSPSSODescriptor(SAMLConstants.SAML20P_NS);
      sso.setAuthnRequestsSigned(true);

      final SamlSpConfigurationProperties.Metadata metadataProps = props.getMetadata();
      if (metadataProps == null) {
        return;
      }

      // Extensions - Entity Categories
      //
      if (metadataProps.getEntityCategories() != null && !metadataProps.getEntityCategories().isEmpty()) {
        final Extensions extensions = Optional.ofNullable(entityDescriptor.getExtensions())
            .orElseGet(() -> ExtensionsBuilder.builder().build());

        extensions.getUnknownXMLObjects()
            .add(EntityAttributesBuilder.builder()
                .entityCategoriesAttribute(metadataProps.getEntityCategories())
                .build());

        entityDescriptor.setExtensions(extensions);
      }

      // SSOSPDescriptor
      //
      sso.setWantAssertionsSigned(metadataProps.isWantAssertionsSigned());

      // NameIDFormats

      // UIInfo
      //

      // Organization and ContactPerson

      // TODO

    };

  }

  @Bean
  FilterRegistrationBean<Saml2MetadataFilter> metadata(
      final RelyingPartyRegistrationResolver registrations,
      final Saml2MetadataResolver saml2MetadataResolver) {
    final Saml2MetadataFilter metadata = new Saml2MetadataFilter(registrations, saml2MetadataResolver);
    metadata.setRequestMatcher(new AntPathRequestMatcher("/saml2/metadata/{registrationId}", "GET"));
    final FilterRegistrationBean<Saml2MetadataFilter> filter = new FilterRegistrationBean<>(metadata);
    filter.setOrder(-101);
    return filter;
  }

  @Bean
  Saml2AuthenticationRequestResolver saml2AuthenticationRequestResolver(
      final RelyingPartyRegistrationResolver rpRegistrationResolver) {
    final OpenSaml5AuthenticationRequestResolver authenticationRequestResolver =
        new OpenSaml5AuthenticationRequestResolver(rpRegistrationResolver);
    authenticationRequestResolver.setAuthnRequestCustomizer(authnRequestCustomizer());
    return authenticationRequestResolver;
  }

  private static Consumer<AuthnRequestContext> authnRequestCustomizer() {
    return (c) -> {
      final AuthnRequest authnRequest = c.getAuthnRequest();
      authnRequest.setForceAuthn(true);
      authnRequest.getIssuer().setFormat(NameID.ENTITY);
      final NameIDPolicy nameIdPolicy =
          (NameIDPolicy) XMLObjectSupport.buildXMLObject(NameIDPolicy.DEFAULT_ELEMENT_NAME);
      nameIdPolicy.setAllowCreate(true);
      nameIdPolicy.setFormat(NameID.PERSISTENT);
      authnRequest.setNameIDPolicy(nameIdPolicy);

      // TODO: RequestAuthnContext
    };
  }

  @Bean
  RelyingPartyRegistrationRepository relayingPartyRepository(final SamlSpConfigurationProperties properties)
      throws Exception {
    final PkiCredential credential = this.loadCredential(properties.getCredential());
    final RelyingPartyRegistration relayingParty = RelyingPartyRegistrations
        //.fromMetadataLocation("https://idp.sandbox.swedenconnect.se/idp/metadata/idp.xml")
        .fromMetadata(properties.getIdpMetadataLocation().getInputStream())
        .entityId(properties.getEntityId())
        //        .assertionConsumerServiceLocation(properties.getAssertionConsumerUrl())
        .registrationId(properties.getRegistrationId())
        .assertingPartyDetails(b -> b.wantAuthnRequestsSigned(true))
        .signingX509Credentials(
            (c) -> c.add(Saml2X509Credential.signing(credential.getPrivateKey(), credential.getCertificate())))
        .decryptionX509Credentials(
            (c) -> c.add(Saml2X509Credential.decryption(credential.getPrivateKey(), credential.getCertificate())))
        .build();
    return new InMemoryRelyingPartyRegistrationRepository(relayingParty);
  }

  private PkiCredential loadCredential(final PkiCredentialConfigurationProperties props) throws Exception {
    return PkiCredentialFactory.createCredential(props, this.resourceLoader,
        this.credentialBundles.getCredentialProvider(), this.credentialBundles.getKeyStoreProvider(), null);
  }

  @Bean
  ExtendedSaml2AuthenticationTokenConverter extendedSaml2AuthenticationTokenConverter(
      final RelyingPartyRegistrationResolver relyingPartyRegistrationResolver) {
    return new ExtendedSaml2AuthenticationTokenConverter(relyingPartyRegistrationResolver);
  }

  @Bean
  OpenSaml5AuthenticationProvider openSaml5AuthenticationProvider() {
    final OpenSaml5AuthenticationProvider provider = new OpenSaml5AuthenticationProvider();
    provider.setResponseAuthenticationConverter(this.responseAuthenticationConverter);
    return provider;
  }

}
