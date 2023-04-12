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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.ext.saml2mdattr.EntityAttributes;
import org.opensaml.saml.ext.saml2mdui.UIInfo;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.metadata.ContactPersonTypeEnumeration;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.Extensions;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.X509Credential;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.xml.XMLParserException;
import se.swedenconnect.opensaml.common.utils.LocalizedString;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorContainer;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorUtils;
import se.swedenconnect.opensaml.saml2.metadata.build.ContactPersonBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.EntityAttributesBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.EntityDescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.ExtensionsBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.IDPSSODescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.KeyDescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.LogoBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.OrganizationBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.SingleSignOnServiceBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.UIInfoBuilder;
import se.swedenconnect.security.credential.opensaml.OpenSamlCredential;
import se.swedenconnect.spring.saml.idp.attributes.nameid.NameIDGeneratorFactory;
import se.swedenconnect.spring.saml.idp.authentication.provider.UserAuthenticationProvider;
import se.swedenconnect.spring.saml.idp.settings.IdentityProviderSettings;
import se.swedenconnect.spring.saml.idp.settings.MetadataSettings;
import se.swedenconnect.spring.saml.idp.settings.MetadataSettings.ContactPersonType;
import se.swedenconnect.spring.saml.idp.settings.MetadataSettings.UIInfoSettings;
import se.swedenconnect.spring.saml.idp.web.filters.Saml2IdpMetadataEndpointFilter;

/**
 * Configurer for the metadata publishing endpoint.
 *
 * @author Martin Lindström
 */
@Slf4j
public class Saml2IdpMetadataEndpointConfigurer extends AbstractSaml2Configurer {

  /** The request matcher. */
  private RequestMatcher requestMatcher;

  /** For customizing metadata. */
  private Customizer<EntityDescriptor> entityDescriptorCustomizer = Customizer.withDefaults();

  /** The metadata builder. */
  private EntityDescriptorBuilder entityDescriptorBuilder;

  /**
   * Constructor restricted for internal use.
   *
   * @param objectPostProcessor the post processor
   */
  Saml2IdpMetadataEndpointConfigurer(final ObjectPostProcessor<Object> objectPostProcessor) {
    super(objectPostProcessor);
  }

  /**
   * Sets the {@code Customizer} providing access to the {@link EntityDescriptor} allowing the ability to customize how
   * the published IdP metadata is constructed.
   *
   * @param metadataCustomizer the {@code Customizer} providing access to the {@link EntityDescriptor}
   * @return the {@link Saml2IdpMetadataEndpointConfigurer} for further configuration
   */
  public Saml2IdpMetadataEndpointConfigurer entityDescriptorCustomizer(
      final Customizer<EntityDescriptor> metadataCustomizer) {
    this.entityDescriptorCustomizer = Objects.requireNonNull(metadataCustomizer, "metadataCustomizer must not be null");
    return this;
  }

  /** {@inheritDoc} */
  @Override
  void init(final HttpSecurity httpSecurity) {
    final IdentityProviderSettings settings = Saml2IdpConfigurerUtils.getIdentityProviderSettings(httpSecurity);
    this.requestMatcher = new AntPathRequestMatcher(
        settings.getEndpoints().getMetadataEndpoint(), HttpMethod.GET.name());
  }

  /** {@inheritDoc} */
  @Override
  void configure(final HttpSecurity httpSecurity) {

    final IdentityProviderSettings settings = Saml2IdpConfigurerUtils.getIdentityProviderSettings(httpSecurity);
    
    if (settings.getMetadata() == null) {
      log.warn("No configuration for SAML metadata provided - IdP will not expose SAML metadata");
      return;
    }

    final Collection<UserAuthenticationProvider> providers =
        Saml2IdpConfigurerUtils.getSaml2UserAuthenticationProviders(httpSecurity);

    // Build metadata ...
    //
    try {
      if (settings.getMetadata().getTemplate() != null) {
        final EntityDescriptor template = (EntityDescriptor) XMLObjectSupport.unmarshallFromInputStream(
            XMLObjectProviderRegistrySupport.getParserPool(), settings.getMetadata().getTemplate().getInputStream());
        this.entityDescriptorBuilder = new EntityDescriptorBuilder(template);
      }
      else {
        this.entityDescriptorBuilder = new EntityDescriptorBuilder();
      }
      this.entityDescriptorBuilder.entityID(settings.getEntityId());
      this.entityDescriptorBuilder.cacheDuration(settings.getMetadata().getCacheDuration());

      // EntityAttributes
      //
      final EntityAttributesBuilder entityAttributesBuilder = EntityAttributesBuilder.builder();
      Extensions extensions = this.entityDescriptorBuilder.object().getExtensions();
      if (extensions != null) {
        final EntityAttributes entityAttributes =
            EntityDescriptorUtils.getMetadataExtension(extensions, EntityAttributes.class);
        if (entityAttributes != null) {
          entityAttributesBuilder.attributes(entityAttributes.getAttributes());
          extensions.getUnknownXMLObjects().removeIf(o -> EntityAttributes.class.isAssignableFrom(o.getClass()));
        }
      }
      else {
        extensions = (Extensions) XMLObjectSupport.buildXMLObject(Extensions.DEFAULT_ELEMENT_NAME);
      }
      final List<String> authnContextUris = providers.stream()
          .map(UserAuthenticationProvider::getSupportedAuthnContextUris)
          .flatMap(Collection::stream)
          .distinct()
          .collect(Collectors.toList());
      if (!authnContextUris.isEmpty()) {
        entityAttributesBuilder.assuranceCertificationAttribute(authnContextUris);
      }
      final List<String> entityCategories = providers.stream()
          .map(UserAuthenticationProvider::getEntityCategories)
          .flatMap(Collection::stream)
          .distinct()
          .collect(Collectors.toList());
      if (!entityCategories.isEmpty()) {
        entityAttributesBuilder.entityCategoriesAttribute(entityCategories);
      }

      extensions.getUnknownXMLObjects().add(entityAttributesBuilder.build());
      this.entityDescriptorBuilder.extensions(extensions);

      final IDPSSODescriptor existingSsoDescriptor =
          this.entityDescriptorBuilder.object().getIDPSSODescriptor(SAMLConstants.SAML20P_NS);
      final IDPSSODescriptorBuilder descBuilder = existingSsoDescriptor != null
          ? new IDPSSODescriptorBuilder(existingSsoDescriptor, true)
          : new IDPSSODescriptorBuilder();

      descBuilder.wantAuthnRequestsSigned(settings.getRequiresSignedRequests());

      final UIInfo uiInfo = buildUiInfo(settings);
      if (uiInfo != null) {
        final ExtensionsBuilder extensionsBuilder = descBuilder.getExtensionsBuilder();
        extensionsBuilder.extensions(uiInfo);
        descBuilder.extensions(extensionsBuilder.build());
      }

      final List<KeyDescriptor> keyDescriptors = new ArrayList<>();
      boolean signAssigned = false;
      boolean encryptAssigned = false;
      if (settings.getCredentials().getSignCredential() != null) {
        signAssigned = true;
        keyDescriptors.add(
            KeyDescriptorBuilder.builder()
                .use(UsageType.SIGNING)
                .certificate(settings.getCredentials().getSignCredential().getCertificate())
                .keyName(settings.getCredentials().getSignCredential().getName())
                .build());
      }
      if (settings.getCredentials().getFutureSignCertificate() != null) {
        keyDescriptors.add(
            KeyDescriptorBuilder.builder()
                .use(UsageType.SIGNING)
                .certificate(settings.getCredentials().getFutureSignCertificate())
                .build());
      }
      if (settings.getCredentials().getEncryptCredential() != null) {
        encryptAssigned = true;
        keyDescriptors.add(
            KeyDescriptorBuilder.builder()
                .use(UsageType.ENCRYPTION)
                .certificate(settings.getCredentials().getEncryptCredential().getCertificate())
                .keyName(settings.getCredentials().getEncryptCredential().getName())
                .build());
        // TODO: encryption methods
      }
      if (settings.getCredentials().getDefaultCredential() != null && (!signAssigned || !encryptAssigned)) {
        final UsageType usage =
            signAssigned ? UsageType.ENCRYPTION : encryptAssigned ? UsageType.SIGNING : UsageType.UNSPECIFIED;
        keyDescriptors.add(
            KeyDescriptorBuilder.builder()
                .use(usage)
                .certificate(settings.getCredentials().getDefaultCredential().getCertificate())
                .keyName(settings.getCredentials().getDefaultCredential().getName())
                .build());
      }
      descBuilder.keyDescriptors(keyDescriptors);

      // NameID formats
      //
      final NameIDGeneratorFactory nameIdGenerator = httpSecurity.getSharedObject(NameIDGeneratorFactory.class);
      final List<String> nameIdFormats = nameIdGenerator != null
          ? nameIdGenerator.getSupportedFormats()
          : List.of(NameID.PERSISTENT, NameID.TRANSIENT);
      descBuilder.nameIDFormats(nameIdFormats);

      final List<SingleSignOnService> ssoServices = new ArrayList<>();
      ssoServices.add(SingleSignOnServiceBuilder.builder()
          .redirectBinding()
          .location(settings.getBaseUrl() + settings.getEndpoints().getRedirectAuthnEndpoint())
          .build());
      ssoServices.add(SingleSignOnServiceBuilder.builder()
          .postBinding()
          .location(settings.getBaseUrl() + settings.getEndpoints().getPostAuthnEndpoint())
          .build());

      // Optional Holder-of-key support
      //
      if (settings.getEndpoints().getHokRedirectAuthnEndpoint() != null) {
        ssoServices.add(SingleSignOnServiceBuilder.builder()
            .hokRedirectBinding()
            .location((settings.getHokBaseUrl() != null ? settings.getHokBaseUrl() : settings.getBaseUrl())
                + settings.getEndpoints().getHokRedirectAuthnEndpoint())
            .build());
      }
      if (settings.getEndpoints().getHokPostAuthnEndpoint() != null) {
        ssoServices.add(SingleSignOnServiceBuilder.builder()
            .hokPostBinding()
            .location((settings.getHokBaseUrl() != null ? settings.getHokBaseUrl() : settings.getBaseUrl())
                + settings.getEndpoints().getHokPostAuthnEndpoint())
            .build());
      }

      descBuilder.singleSignOnServices(ssoServices);

      this.entityDescriptorBuilder.ssoDescriptor(descBuilder.build());

      // Organization
      //
      if (settings.getMetadata().getOrganization() != null) {
        final OrganizationBuilder b = OrganizationBuilder.builder();
        b.organizationNames(Optional.ofNullable(settings.getMetadata().getOrganization().getNames())
            .map(n -> n.entrySet().stream()
                .map(e -> new LocalizedString(e.getValue(), e.getKey()))
                .collect(Collectors.toList()))
            .orElse(null));
        b.organizationDisplayNames(Optional.ofNullable(settings.getMetadata().getOrganization().getDisplayNames())
            .map(n -> n.entrySet().stream()
                .map(e -> new LocalizedString(e.getValue(), e.getKey()))
                .collect(Collectors.toList()))
            .orElse(null));
        b.organizationURLs(Optional.ofNullable(settings.getMetadata().getOrganization().getUrls())
            .map(n -> n.entrySet().stream()
                .map(e -> new LocalizedString(e.getValue(), e.getKey()))
                .collect(Collectors.toList()))
            .orElse(null));

        this.entityDescriptorBuilder.organization(b.build());
      }

      // ContactPerson:s
      //
      if (settings.getMetadata().getContactPersons() != null) {
        this.entityDescriptorBuilder.contactPersons(
            settings.getMetadata().getContactPersons().entrySet().stream()
                .map(e -> ContactPersonBuilder.builder()
                    .type(toOpenSamlEnum(e.getKey()))
                    .company(e.getValue().getCompany())
                    .givenName(e.getValue().getGivenName())
                    .surname(e.getValue().getSurname())
                    .emailAddresses(e.getValue().getEmailAddresses())
                    .telephoneNumbers(e.getValue().getTelephoneNumbers())
                    .build())
                .collect(Collectors.toList()));
      }

    }
    catch (final IOException | XMLParserException | UnmarshallingException e) {
      throw new IllegalArgumentException("Failed to construct IdP metadata - " + e.getMessage(), e);
    }

    this.entityDescriptorCustomizer.customize(this.entityDescriptorBuilder.object());

    final X509Credential metadataSigning;
    if (settings.getCredentials().getMetadataSignCredential() != null) {
      metadataSigning = new OpenSamlCredential(settings.getCredentials().getMetadataSignCredential());
    }
    else if (settings.getCredentials().getDefaultCredential() != null) {
      metadataSigning = new OpenSamlCredential(settings.getCredentials().getDefaultCredential());
    }
    else {
      log.warn("No metadata signing credential configured - IdP metadata will not be signed");
      metadataSigning = null;
    }
    final EntityDescriptorContainer container =
        new EntityDescriptorContainer(this.entityDescriptorBuilder.build(), metadataSigning);
    container.setValidity(settings.getMetadata().getValidityPeriod());

    final Saml2IdpMetadataEndpointFilter filter =
        new Saml2IdpMetadataEndpointFilter(container, this.requestMatcher);
    httpSecurity.addFilterBefore(postProcess(filter), AbstractPreAuthenticatedProcessingFilter.class);
  }

  /** {@inheritDoc} */
  @Override
  RequestMatcher getRequestMatcher() {
    return this.requestMatcher;
  }

  /**
   * Builds an {@link UIInfo} element.
   * 
   * @param settings the IdP settings
   * @return an {@link UIInfo} element or {@code null}
   */
  private static UIInfo buildUiInfo(final IdentityProviderSettings settings) {
    final UIInfoSettings uiSettings = Optional.ofNullable(settings.getMetadata())
        .map(MetadataSettings::getUiInfo)
        .orElse(null);
    if (uiSettings == null) {
      return null;
    }

    final UIInfoBuilder uiBuilder = UIInfoBuilder.builder();
    uiBuilder.displayNames(Optional.ofNullable(uiSettings.getDisplayNames())
        .map(d -> d.entrySet().stream().map(e -> new LocalizedString(e.getValue(), e.getKey()))
            .collect(Collectors.toList()))
        .orElse(null));
    uiBuilder.descriptions(Optional.ofNullable(uiSettings.getDescriptions())
        .map(d -> d.entrySet().stream().map(e -> new LocalizedString(e.getValue(), e.getKey()))
            .collect(Collectors.toList()))
        .orElse(null));

    uiBuilder.logos(Optional.ofNullable(uiSettings.getLogotypes())
        .map(l -> l.stream()
            .map(logo -> LogoBuilder.builder()
                .url(logo.getPath() != null
                    ? settings.getBaseUrl() + logo.getPath()
                    : logo.getUrl())
                .language(logo.getLanguageTag())
                .height(logo.getHeight())
                .width(logo.getWidth())
                .build())
            .collect(Collectors.toList()))
        .orElse(null));

    return uiBuilder.build();
  }

  private static ContactPersonTypeEnumeration toOpenSamlEnum(final ContactPersonType type) {
    for (final ContactPersonTypeEnumeration e : ContactPersonTypeEnumeration.values()) {
      if (e.toString().equals(type.name())) {
        return e;
      }
    }
    throw new IllegalArgumentException("Unknown ContactPerson type: " + type.name());
  }

}
