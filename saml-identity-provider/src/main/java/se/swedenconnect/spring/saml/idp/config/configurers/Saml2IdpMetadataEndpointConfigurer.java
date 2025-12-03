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
package se.swedenconnect.spring.saml.idp.config.configurers;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import javax.xml.namespace.QName;

import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.ext.saml2alg.DigestMethod;
import org.opensaml.saml.ext.saml2alg.SigningMethod;
import org.opensaml.saml.ext.saml2mdattr.EntityAttributes;
import org.opensaml.saml.ext.saml2mdui.UIInfo;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.metadata.ContactPerson;
import org.opensaml.saml.saml2.metadata.ContactPersonTypeEnumeration;
import org.opensaml.saml.saml2.metadata.EncryptionMethod;
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
import org.springframework.util.StringUtils;

import lombok.extern.slf4j.Slf4j;
import net.shibboleth.shared.xml.XMLParserException;
import se.swedenconnect.opensaml.common.utils.LocalizedString;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorContainer;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorUtils;
import se.swedenconnect.opensaml.saml2.metadata.build.ContactPersonBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.DigestMethodBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.EncryptionMethodBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.EntityAttributesBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.EntityDescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.IDPSSODescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.KeyDescriptorBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.LogoBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.OrganizationBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.SigningMethodBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.SingleSignOnServiceBuilder;
import se.swedenconnect.opensaml.saml2.metadata.build.UIInfoBuilder;
import se.swedenconnect.opensaml.sweid.saml2.authn.psc.RequestedPrincipalSelection;
import se.swedenconnect.opensaml.sweid.saml2.authn.psc.build.MatchValueBuilder;
import se.swedenconnect.opensaml.sweid.saml2.authn.psc.build.RequestedPrincipalSelectionBuilder;
import se.swedenconnect.opensaml.sweid.saml2.metadata.entitycategory.EntityCategoryConstants;
import se.swedenconnect.opensaml.sweid.saml2.metadata.ext.OrganizationNumber;
import se.swedenconnect.security.credential.opensaml.OpenSamlCredential;
import se.swedenconnect.spring.saml.idp.attributes.nameid.NameIDGeneratorFactory;
import se.swedenconnect.spring.saml.idp.authentication.provider.UserAuthenticationProvider;
import se.swedenconnect.spring.saml.idp.settings.IdentityProviderSettings;
import se.swedenconnect.spring.saml.idp.settings.MetadataSettings;
import se.swedenconnect.spring.saml.idp.settings.MetadataSettings.ContactPersonSettings;
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
            Objects.requireNonNull(XMLObjectProviderRegistrySupport.getParserPool()),
            settings.getMetadata().getTemplate().getInputStream());
        this.entityDescriptorBuilder = new EntityDescriptorBuilder(template);
      }
      else {
        this.entityDescriptorBuilder = new EntityDescriptorBuilder();
      }
      this.entityDescriptorBuilder.entityID(settings.getEntityId());
      this.entityDescriptorBuilder.cacheDuration(settings.getMetadata().getCacheDuration());

      final Extensions extensions = Optional.ofNullable(this.entityDescriptorBuilder.object().getExtensions())
          .orElseGet(() -> {
            final Extensions e = (Extensions) XMLObjectSupport.buildXMLObject(Extensions.DEFAULT_ELEMENT_NAME);
            this.entityDescriptorBuilder.extensions(e);
            return e;
          });

      // EntityAttributes
      //
      final EntityAttributesBuilder entityAttributesBuilder = EntityAttributesBuilder.builder();
      final EntityAttributes entityAttributes =
          EntityDescriptorUtils.getMetadataExtension(extensions, EntityAttributes.class);
      if (entityAttributes != null) {
        entityAttributesBuilder.attributes(entityAttributes.getAttributes());
        extensions.getUnknownXMLObjects().removeIf(o -> EntityAttributes.class.isAssignableFrom(o.getClass()));
      }

      final List<String> authnContextUris = providers.stream()
          .map(UserAuthenticationProvider::getSupportedAuthnContextUris)
          .flatMap(Collection::stream)
          .distinct()
          .collect(Collectors.toList());
      if (!authnContextUris.isEmpty()) {
        entityAttributesBuilder.assuranceCertificationAttribute(authnContextUris);
      }
      final List<String> entityCategories = new ArrayList<>();
      providers.stream()
          .map(UserAuthenticationProvider::getEntityCategories)
          .flatMap(Collection::stream)
          .distinct()
          .forEach(entityCategories::add);
      if (!entityCategories.isEmpty()) {
        if (settings.getSupportsUserMessage() && !entityCategories.contains(
            EntityCategoryConstants.GENERAL_CATEGORY_SUPPORTS_USER_MESSAGE.getUri())) {
          entityCategories.add(EntityCategoryConstants.GENERAL_CATEGORY_SUPPORTS_USER_MESSAGE.getUri());
        }
        entityAttributesBuilder.entityCategoriesAttribute(entityCategories);
      }

      extensions.getUnknownXMLObjects().add(entityAttributesBuilder.build());

      if (settings.getMetadata().getDigestMethods() != null
          && !settings.getMetadata().getDigestMethodsUnderRole()) {
        extensions.getUnknownXMLObjects().removeIf(o -> DigestMethod.class.isAssignableFrom(o.getClass()));
        settings.getMetadata().getDigestMethods().stream()
            .filter(StringUtils::hasText)
            .forEach(d -> extensions.getUnknownXMLObjects().add(DigestMethodBuilder.builder().algorithm(d).build()));
      }
      if (settings.getMetadata().getSigningMethods() != null
          && !settings.getMetadata().getSigningMethodsUnderRole()) {
        extensions.getUnknownXMLObjects().removeIf(o -> SigningMethod.class.isAssignableFrom(o.getClass()));
        settings.getMetadata().getSigningMethods().stream()
            .filter(s -> StringUtils.hasText(s.getAlgorithm()))
            .forEach(s -> extensions.getUnknownXMLObjects().add(
                SigningMethodBuilder.signingMethod(s.getAlgorithm(), s.getMinKeySize(), s.getMaxKeySize())));
      }

      final IDPSSODescriptor existingSsoDescriptor =
          this.entityDescriptorBuilder.object().getIDPSSODescriptor(SAMLConstants.SAML20P_NS);
      final IDPSSODescriptorBuilder descBuilder = existingSsoDescriptor != null
          ? new IDPSSODescriptorBuilder(existingSsoDescriptor, true)
          : new IDPSSODescriptorBuilder();

      descBuilder.wantAuthnRequestsSigned(settings.getRequiresSignedRequests());

      final Extensions roleExtensions = Optional.ofNullable(descBuilder.object().getExtensions())
          .orElseGet(() -> (Extensions) XMLObjectSupport.buildXMLObject(Extensions.DEFAULT_ELEMENT_NAME));

      final UIInfo uiInfo = buildUiInfo(settings);
      if (uiInfo != null) {
        roleExtensions.getUnknownXMLObjects().removeIf(o -> UIInfo.class.isAssignableFrom(o.getClass()));
        roleExtensions.getUnknownXMLObjects().add(uiInfo);
      }

      if (settings.getMetadata().getRequestedPrincipalSelection() != null
          && !settings.getMetadata().getRequestedPrincipalSelection().isEmpty()) {
        roleExtensions.getUnknownXMLObjects()
            .removeIf(o -> RequestedPrincipalSelection.class.isAssignableFrom(o.getClass()));

        final RequestedPrincipalSelection rps = RequestedPrincipalSelectionBuilder.builder()
            .matchValues(settings.getMetadata().getRequestedPrincipalSelection().stream()
                .map(a -> MatchValueBuilder.builder().name(a).build())
                .toList())
            .build();
        roleExtensions.getUnknownXMLObjects().add(rps);
      }

      if (settings.getMetadata().getDigestMethods() != null
          && settings.getMetadata().getDigestMethodsUnderRole()) {
        roleExtensions.getUnknownXMLObjects().removeIf(o -> DigestMethod.class.isAssignableFrom(o.getClass()));
        settings.getMetadata().getDigestMethods().stream()
            .filter(StringUtils::hasText)
            .forEach(
                d -> roleExtensions.getUnknownXMLObjects().add(DigestMethodBuilder.builder().algorithm(d).build()));
      }
      if (settings.getMetadata().getSigningMethods() != null
          && settings.getMetadata().getSigningMethodsUnderRole()) {
        roleExtensions.getUnknownXMLObjects().removeIf(o -> SigningMethod.class.isAssignableFrom(o.getClass()));
        settings.getMetadata().getSigningMethods().stream()
            .filter(s -> StringUtils.hasText(s.getAlgorithm()))
            .forEach(s -> roleExtensions.getUnknownXMLObjects().add(
                SigningMethodBuilder.signingMethod(s.getAlgorithm(), s.getMinKeySize(), s.getMaxKeySize())));
      }

      if (descBuilder.object().getExtensions() == null && !roleExtensions.getUnknownXMLObjects().isEmpty()) {
        descBuilder.extensions(roleExtensions);
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
        final KeyDescriptorBuilder kdBuilder = KeyDescriptorBuilder.builder()
            .use(UsageType.ENCRYPTION)
            .certificate(settings.getCredentials().getEncryptCredential().getCertificate())
            .keyName(settings.getCredentials().getEncryptCredential().getName());

        if (settings.getMetadata().getEncryptionMethods() != null) {
          kdBuilder.encryptionMethodsExt(settings.getMetadata().getEncryptionMethods().stream()
              .filter(e -> StringUtils.hasText(e.getAlgorithm()))
              .map(e -> {
                final EncryptionMethodBuilder builder = EncryptionMethodBuilder.builder()
                    .algorithm(e.getAlgorithm());

                if (e.getKeySize() != null) {
                  builder.keySize(e.getKeySize());
                }
                if (e.getOaepParams() != null) {
                  builder.oAEPparams(e.getOaepParams());
                }
                final EncryptionMethod em = builder.build();

                if (StringUtils.hasText(e.getDigestMethod())) {
                  final org.opensaml.xmlsec.signature.DigestMethod dm =
                      (org.opensaml.xmlsec.signature.DigestMethod) XMLObjectSupport.buildXMLObject(
                          org.opensaml.xmlsec.signature.DigestMethod.DEFAULT_ELEMENT_NAME);
                  dm.setAlgorithm(e.getDigestMethod());
                  em.getUnknownXMLObjects().add(dm);
                }
                return em;
              })
              .toList());
        }

        keyDescriptors.add(kdBuilder.build());
      }
      if (settings.getCredentials().getDefaultCredential() != null && (!signAssigned || !encryptAssigned)) {
        final UsageType usage =
            signAssigned ? UsageType.ENCRYPTION : encryptAssigned ? UsageType.SIGNING : UsageType.UNSPECIFIED;

        final KeyDescriptorBuilder kdBuilder = KeyDescriptorBuilder.builder()
            .use(usage)
            .certificate(settings.getCredentials().getDefaultCredential().getCertificate())
            .keyName(settings.getCredentials().getDefaultCredential().getName());

        if (usage == UsageType.ENCRYPTION || usage == UsageType.UNSPECIFIED) {
          if (settings.getMetadata().getEncryptionMethods() != null) {
            kdBuilder.encryptionMethodsExt(settings.getMetadata().getEncryptionMethods().stream()
                .filter(e -> StringUtils.hasText(e.getAlgorithm()))
                .map(e -> {
                  final EncryptionMethodBuilder builder = EncryptionMethodBuilder.builder()
                      .algorithm(e.getAlgorithm());

                  if (e.getKeySize() != null) {
                    builder.keySize(e.getKeySize());
                  }
                  if (e.getOaepParams() != null) {
                    builder.oAEPparams(e.getOaepParams());
                  }
                  final EncryptionMethod em = builder.build();

                  if (StringUtils.hasText(e.getDigestMethod())) {
                    final org.opensaml.xmlsec.signature.DigestMethod dm =
                        (org.opensaml.xmlsec.signature.DigestMethod) XMLObjectSupport.buildXMLObject(
                            org.opensaml.xmlsec.signature.DigestMethod.DEFAULT_ELEMENT_NAME);
                    dm.setAlgorithm(e.getDigestMethod());
                    em.getUnknownXMLObjects().add(dm);
                  }
                  return em;
                })
                .toList());
          }
        }

        keyDescriptors.add(kdBuilder.build());
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

        if (StringUtils.hasText(settings.getMetadata().getOrganization().getNumber())) {
          final OrganizationNumber number =
              (OrganizationNumber) XMLObjectSupport.buildXMLObject(OrganizationNumber.DEFAULT_ELEMENT_NAME);
          number.setValue(settings.getMetadata().getOrganization().getNumber());

          final Extensions orgext = (Extensions) XMLObjectSupport.buildXMLObject(Extensions.DEFAULT_ELEMENT_NAME);
          orgext.getUnknownXMLObjects().add(number);

          b.object().setExtensions(orgext);
        }

        this.entityDescriptorBuilder.organization(b.build());
      }

      // ContactPerson:s
      //
      if (settings.getMetadata().getContactPersons() != null) {
        this.entityDescriptorBuilder.contactPersons(
            settings.getMetadata().getContactPersons().entrySet().stream()
                .map(e -> toContactPerson(e.getKey(), e.getValue()))
                .toList());
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
    httpSecurity.addFilterBefore(this.postProcess(filter), AbstractPreAuthenticatedProcessingFilter.class);
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

  /**
   * Creates a {@link ContactPerson} element.
   *
   * @param type the type
   * @param cpSetting the settings
   * @return a {@link ContactPerson}
   */
  private static ContactPerson toContactPerson(final ContactPersonType type, final ContactPersonSettings cpSetting) {

    final ContactPerson cp = ContactPersonBuilder.builder()
        .type(toOpenSamlEnum(type))
        .company(cpSetting.getCompany())
        .givenName(cpSetting.getGivenName())
        .surname(cpSetting.getSurname())
        .emailAddresses(cpSetting.getEmailAddresses())
        .telephoneNumbers(cpSetting.getTelephoneNumbers())
        .build();

    if (type == ContactPersonType.security) {
      cp.getUnknownAttributes().put(new QName("http://refeds.org/metadata", "contactType", "remd"),
          "http://refeds.org/metadata/contactType/security");
    }

    return cp;
  }

  private static ContactPersonTypeEnumeration toOpenSamlEnum(final ContactPersonType type) {
    if (type == ContactPersonType.security) {
      return ContactPersonTypeEnumeration.OTHER;
    }
    for (final ContactPersonTypeEnumeration e : ContactPersonTypeEnumeration.values()) {
      if (e.toString().equals(type.name())) {
        return e;
      }
    }
    throw new IllegalArgumentException("Unknown ContactPerson type: " + type.name());
  }

}
