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
package se.swedenconnect.spring.saml.idp.autoconfigure.settings;

import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.Import;

import lombok.Setter;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.spring.saml.idp.config.configurers.Saml2IdpConfigurer;
import se.swedenconnect.spring.saml.idp.events.Saml2IdpEventPublisher;
import se.swedenconnect.spring.saml.idp.settings.AssertionSettings;
import se.swedenconnect.spring.saml.idp.settings.CredentialSettings;
import se.swedenconnect.spring.saml.idp.settings.EndpointSettings;
import se.swedenconnect.spring.saml.idp.settings.IdentityProviderSettings;
import se.swedenconnect.spring.saml.idp.settings.MetadataSettings;
import se.swedenconnect.spring.saml.idp.settings.MetadataSettings.EncryptionMethodSettings;
import se.swedenconnect.spring.saml.idp.settings.MetadataSettings.SigningMethodSettings;

/**
 * Configuration class for Identity Provider general settings.
 *
 * @author Martin Lindström
 */
@AutoConfiguration
@EnableConfigurationProperties(IdentityProviderConfigurationProperties.class)
@Import({ CredentialConfiguration.class, MetadataResolverConfiguration.class })
@DependsOn("openSAML")
public class IdentityProviderAutoConfiguration {

  @Setter
  @Autowired(required = false)
  private IdentityProviderConfigurationProperties properties;

  @Setter
  @Autowired(required = false)
  @Qualifier("saml.idp.credentials.Default")
  private PkiCredential defaultCredential;

  @Setter
  @Autowired(required = false)
  @Qualifier("saml.idp.credentials.Sign")
  private PkiCredential signCredential;

  @Setter
  @Autowired(required = false)
  @Qualifier("saml.idp.credentials.FutureSign")
  private X509Certificate futureSignCertificate;

  @Setter
  @Autowired(required = false)
  @Qualifier("saml.idp.credentials.Encrypt")
  private PkiCredential encryptCredential;

  @Setter
  @Autowired(required = false)
  @Qualifier("saml.idp.credentials.PreviousEncrypt")
  private PkiCredential previousEncryptCredential;

  @Setter
  @Autowired(required = false)
  @Qualifier("saml.idp.credentials.MetadataSign")
  private PkiCredential metadataSignCredential;

  @Setter
  @Autowired(required = false)
  @Qualifier("saml.idp.metadata.Provider")
  private MetadataResolver metadataProvider;

  @ConditionalOnMissingBean
  @Bean
  IdentityProviderSettings identityProviderSettings() {
    if (this.properties == null) {
      return IdentityProviderSettings.builder().build();
    }
    final IdentityProviderSettings.Builder builder = IdentityProviderSettings.builder()
        .entityId(this.properties.getEntityId())
        .baseUrl(this.properties.getBaseUrl())
        .hokBaseUrl(this.properties.getHokBaseUrl())
        .requiresSignedRequests(this.properties.getRequiresSignedRequests())
        .clockSkewAdjustment(this.properties.getClockSkewAdjustment())
        .maxMessageAge(this.properties.getMaxMessageAge())
        .ssoDurationLimit(this.properties.getSsoDurationLimit())
        .credentials(CredentialSettings.builder()
            .defaultCredential(this.defaultCredential)
            .signCredential(this.signCredential)
            .futureSignCertificate(this.futureSignCertificate)
            .encryptCredential(this.encryptCredential)
            .previousEncryptCredential(this.previousEncryptCredential)
            .metadataSignCredential(this.metadataSignCredential)
            .build());

    if (this.properties.getEndpoints() != null) {
      builder.endpoints(
          EndpointSettings.builder()
              .redirectAuthnEndpoint(this.properties.getEndpoints().getRedirectAuthn())
              .postAuthnEndpoint(this.properties.getEndpoints().getPostAuthn())
              .hokRedirectAuthnEndpoint(this.properties.getEndpoints().getHokRedirectAuthn())
              .hokPostAuthnEndpoint(this.properties.getEndpoints().getHokPostAuthn())
              .metadataEndpoint(this.properties.getEndpoints().getMetadata())
              .build());
    }
    if (this.properties.getAssertions() != null) {
      builder.assertionSettings(
          AssertionSettings.builder()
              .encryptAssertions(this.properties.getAssertions().getEncrypt())
              .notBeforeDuration(this.properties.getAssertions().getNotBefore())
              .notOnOrAfterDuration(this.properties.getAssertions().getNotAfter())
              .build());
    }
    if (this.properties.getMetadata() != null) {
      final MetadataSettings.Builder mdBuilder = MetadataSettings.builder()
          .template(this.properties.getMetadata().getTemplate())
          .cacheDuration(this.properties.getMetadata().getCacheDuration())
          .validityPeriod(this.properties.getMetadata().getValidityPeriod())
          .digestMethods(this.properties.getMetadata().getDigestMethods())
          .digestMethodsUnderRole(this.properties.getMetadata().isIncludeDigestMethodsUnderRole())
          .signingMethods(Optional.ofNullable(this.properties.getMetadata().getSigningMethods())
              .map(list -> list.stream()
                  .map(s -> SigningMethodSettings.builder()
                      .algorithm(s.getAlgorithm())
                      .minKeySize(s.getMinKeySize())
                      .maxKeySize(s.getMaxKeySize())
                      .build())
                  .toList())
              .orElse(null))
          .signingMethodsUnderRole(this.properties.getMetadata().isIncludeSigningMethodsUnderRole())
          .encryptionMethods(Optional.ofNullable(this.properties.getMetadata().getEncryptionMethods())
              .map(list -> list.stream()
                  .map(m -> EncryptionMethodSettings.builder()
                      .algorithm(m.getAlgorithm())
                      .keySize(m.getKeySize())
                      .oaepParams(m.getOaepParams())
                      .digestMethod(m.getDigestMethod())
                      .build())
                  .toList())
              .orElse(null))
          .requestedPrincipalSelection(this.properties.getMetadata().getRequestedPrincipalSelection());

      if (this.properties.getMetadata().getUiInfo() != null) {
        final MetadataSettings.UIInfoSettings.Builder uiBuilder = MetadataSettings.UIInfoSettings.builder()
            .displayNames(this.properties.getMetadata().getUiInfo().getDisplayNames())
            .descriptions(this.properties.getMetadata().getUiInfo().getDescriptions());
        if (this.properties.getMetadata().getUiInfo().getLogotypes() != null) {
          uiBuilder.logotypes(this.properties.getMetadata().getUiInfo().getLogotypes().stream()
              .map(l -> MetadataSettings.UIInfoSettings.LogoSettings.builder()
                  .url(l.getUrl())
                  .path(l.getPath())
                  .width(l.getWidth())
                  .height(l.getHeight())
                  .languageTag(l.getLanguageTag())
                  .build())
              .collect(Collectors.toList()));
        }
        mdBuilder.uiInfo(uiBuilder.build());
      }

      if (this.properties.getMetadata().getOrganization() != null) {
        mdBuilder.organization(MetadataSettings.OrganizationSettings.builder()
            .names(this.properties.getMetadata().getOrganization().getNames())
            .displayNames(this.properties.getMetadata().getOrganization().getDisplayNames())
            .urls(this.properties.getMetadata().getOrganization().getUrls())
            .build());
      }

      if (this.properties.getMetadata().getContactPersons() != null) {
        mdBuilder.contactPersons(this.properties.getMetadata().getContactPersons().entrySet().stream()
            .collect(Collectors.toMap(Map.Entry::getKey,
                e -> MetadataSettings.ContactPersonSettings.builder()
                    .company(e.getValue().getCompany())
                    .givenName(e.getValue().getGivenName())
                    .surname(e.getValue().getSurname())
                    .emailAddresses(e.getValue().getEmailAddresses())
                    .telephoneNumbers(e.getValue().getTelephoneNumbers())
                    .build())));
      }

      builder.metadata(mdBuilder.build());
    }
    if (this.metadataProvider != null) {
      builder.metadataProvider(this.metadataProvider);
    }

    final IdentityProviderSettings settings = builder.build();
    Saml2IdpConfigurer.validateIdentityProviderSettings(settings);

    return settings;

  }

  @ConditionalOnMissingBean
  @Bean
  Saml2IdpEventPublisher saml2IdpEventPublisher(final ApplicationEventPublisher applicationEventPublisher) {
    return new Saml2IdpEventPublisher(applicationEventPublisher);
  }

}
