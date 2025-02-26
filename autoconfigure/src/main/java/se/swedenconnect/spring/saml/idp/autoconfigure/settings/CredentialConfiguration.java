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
package se.swedenconnect.spring.saml.idp.autoconfigure.settings;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.factory.PkiCredentialConfigurationProperties;
import se.swedenconnect.security.credential.factory.PkiCredentialFactory;

import java.security.cert.X509Certificate;

/**
 * Configuration class for IdP credentials.
 *
 * @author Martin Lindström
 */
@Configuration
@EnableConfigurationProperties(IdentityProviderConfigurationProperties.class)
public class CredentialConfiguration {

  /** The properties. */
  private final IdentityProviderConfigurationProperties properties;

  /** The credential factory bean. */
  private final PkiCredentialFactory credentialFactory;

  /**
   * Constructor.
   *
   * @param properties the IdP properties
   * @param credentialFactory the credential factory bean
   */
  public CredentialConfiguration(
      @Autowired(required = false) final IdentityProviderConfigurationProperties properties,
      final PkiCredentialFactory credentialFactory) {
    this.properties = properties;
    this.credentialFactory = credentialFactory;
  }

  @ConditionalOnMissingBean(name = "saml.idp.credentials.Default")
  @Bean("saml.idp.credentials.Default")
  PkiCredential defaultCredential() throws Exception {
    this.assertProperties();
    return this.loadCredential(this.properties.getCredentials().getDefaultCredential());
  }

  @ConditionalOnMissingBean(name = "saml.idp.credentials.Sign")
  @Bean("saml.idp.credentials.Sign")
  PkiCredential signCredential() throws Exception {
    this.assertProperties();
    return this.loadCredential(this.properties.getCredentials().getSign());
  }

  @ConditionalOnMissingBean(name = "saml.idp.credentials.FutureSign")
  @Bean("saml.idp.credentials.FutureSign")
  X509Certificate futureSignCertificate() {
    if (this.properties != null && this.properties.getCredentials() != null) {
      return this.properties.getCredentials().getFutureSign();
    }
    return null;
  }

  @ConditionalOnMissingBean(name = "saml.idp.credentials.Encrypt")
  @Bean("saml.idp.credentials.Encrypt")
  PkiCredential encryptCredential() throws Exception {
    this.assertProperties();
    return this.loadCredential(this.properties.getCredentials().getEncrypt());
  }

  @ConditionalOnMissingBean(name = "saml.idp.credentials.PreviousEncrypt")
  @Bean("saml.idp.credentials.PreviousEncrypt")
  PkiCredential previousEncryptCredential() throws Exception {
    this.assertProperties();
    return this.loadCredential(this.properties.getCredentials().getPreviousEncrypt());
  }

  @ConditionalOnMissingBean(name = "saml.idp.credentials.MetadataSign")
  @Bean("saml.idp.credentials.MetadataSign")
  PkiCredential metadataSignCredential() throws Exception {
    this.assertProperties();
    return this.loadCredential(this.properties.getCredentials().getMetadataSign());
  }

  private void assertProperties() {
    if (this.properties == null) {
      throw new IllegalArgumentException("Missing IdP configuration");
    }
    if (this.properties.getCredentials() == null) {
      throw new IllegalArgumentException("Missing saml.idp.credentials.* configuration");
    }
  }

  private PkiCredential loadCredential(final PkiCredentialConfigurationProperties props) throws Exception {
    if (props == null) {
      return null;
    }
    return this.credentialFactory.createCredential(props);
  }

}
