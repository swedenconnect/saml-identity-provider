/*
 * Copyright 2022-2023 Sweden Connect
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

import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.Import;

import lombok.Setter;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.spring.saml.idp.config.annotation.web.configurers.Saml2IdpConfigurer;
import se.swedenconnect.spring.saml.idp.settings.CredentialSettings;
import se.swedenconnect.spring.saml.idp.settings.EndpointSettings;
import se.swedenconnect.spring.saml.idp.settings.IdentityProviderSettings;
import se.swedenconnect.spring.saml.idp.settings.MetadataProviderSettings;
import se.swedenconnect.spring.saml.idp.settings.MetadataSettings;

/**
 * Configuration class for Identity Provider general settings.
 *
 * @author Martin Lindström
 */
@AutoConfiguration
@EnableConfigurationProperties(IdentityProviderConfigurationProperties.class)
@Import(CredentialConfiguration.class)
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
    if (this.properties.getMetadata() != null) {
      builder.metadata(
          MetadataSettings.builder()
              .template(this.properties.getMetadata().getTemplate())
              .cacheDuration(this.properties.getMetadata().getCacheDuration())
              .validityPeriod(this.properties.getMetadata().getValidityPeriod())
              .entityCategories(this.properties.getMetadata().getEntityCategories())
              .build());
    }
    if (this.metadataProvider != null) {
      builder.metadataProvider(this.metadataProvider);
    }
    else if (this.properties.getMetadataProviders() != null) {
      final MetadataProviderSettings[] settings =
          new MetadataProviderSettings[this.properties.getMetadataProviders().size()];
      int pos = 0;
      for (final MetadataProviderConfigurationProperties p : this.properties.getMetadataProviders()) {
        settings[pos] = MetadataProviderSettings.builder()
            .location(p.getLocation())
            .backupLocation(p.getBackupLocation())
            .mdq(p.getMdq())
            .validationCertificate(p.getValidationCertificate())
            .httpProxy(p.getHttpProxy() != null
                ? MetadataProviderSettings.HttpProxySettings.builder()
                    .host(p.getHttpProxy().getHost())
                    .port(p.getHttpProxy().getPort())
                    .userName(p.getHttpProxy().getUserName())
                    .password(p.getHttpProxy().getPassword())
                    .build()
                : null)
            .build();
      }
      builder.metadataProviderConfiguration(settings);
    }

    final IdentityProviderSettings settings = builder.build();
    Saml2IdpConfigurer.validateIdentityProviderSettings(settings);

    return settings;

  }

}
