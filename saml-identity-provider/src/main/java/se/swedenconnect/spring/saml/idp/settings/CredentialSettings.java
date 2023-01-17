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
package se.swedenconnect.spring.saml.idp.settings;

import java.security.cert.X509Certificate;
import java.util.Map;

import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.util.Assert;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.PkiCredential;

/**
 * Settings for Identity Provider credentials.
 *
 * @author Martin Lindström
 */
public class CredentialSettings extends AbstractSettings {

  private static final long serialVersionUID = 6616974038738634389L;

  /**
   * Constructor.
   *
   * @param settings the settings
   */
  private CredentialSettings(final Map<String, Object> settings) {
    super(settings);
  }

  /**
   * The IdP default credential. A {@link PkiCredential}.
   */
  public static final String DEFAULT_CREDENTIAL = "default";

  /**
   * Gets the default IdP credential.
   *
   * @return the credential or null if not assigned
   */
  public PkiCredential getDefaultCredential() {
    return this.getSetting(DEFAULT_CREDENTIAL);
  }

  /**
   * The IdP signing credential. A {@link PkiCredential}.
   */
  public static final String SIGN_CREDENTIAL = "sign";

  /**
   * Gets the signing IdP credential.
   *
   * @return the credential or null if none is assigned
   */
  public PkiCredential getSignCredential() {
    return this.getSetting(SIGN_CREDENTIAL);
  }

  /**
   * A certificate that will be the future signing certificate. Is set before a key-rollover is performed. A
   * {@link X509Certificate}.
   */
  public static final String FUTURE_SIGN_CERTIFICATE = "future-sign";

  /**
   * Gets the future IdP signing certificate. Assigned before a key-rollover is performed.
   *
   * @return a certificate or null if none is assigned
   */
  public X509Certificate getFutureSignCertificate() {
    return this.getSetting(FUTURE_SIGN_CERTIFICATE);
  }

  /**
   * The IdP encryption credential. A {@link PkiCredential}.
   */
  public static final String ENCRYPT_CREDENTIAL = "encrypt";

  /**
   * Gets the encryption IdP credential.
   *
   * @return the credential or null if none is assigned
   */
  public PkiCredential getEncryptCredential() {
    return this.getSetting(ENCRYPT_CREDENTIAL);
  }

  /**
   * The previous IdP encryption credential. Assigned after a key-rollover. A {@link PkiCredential}.
   */
  public static final String PREVIOUS_ENCRYPT_CREDENTIAL = "previous-encrypt";

  /**
   * Gets the previous encryption IdP credential. Assigned after a key-rollover has been performed.
   *
   * @return the credential or null if none is assigned
   */
  public PkiCredential getPreviousEncryptCredential() {
    return this.getSetting(PREVIOUS_ENCRYPT_CREDENTIAL);
  }

  /**
   * The SAML metadata signing credential. A {@link PkiCredential}.
   */
  public static final String METADATA_SIGN_CREDENTIAL = "metadata-sign";

  /**
   * Gets the credential for signing metadata.
   *
   * @return the credential or null if none has been assigned
   */
  public PkiCredential getMetadataSignCredential() {
    return this.getSetting(METADATA_SIGN_CREDENTIAL);
  }

  /**
   * Constructs a new {@link Builder} with no settings.
   *
   * @return the {@link Builder}
   */
  public static Builder builder() {
    return new Builder();
  }

  /**
   * Constructs a new {@link Builder} with the provided settings.
   *
   * @param settings the settings to initialize the builder
   * @return the builder
   */
  public static Builder withSettings(final Map<String, Object> settings) {
    Assert.notEmpty(settings, "settings cannot be empty");
    return new Builder().settings(s -> s.putAll(settings));
  }

  /**
   * A builder for {@link CredentialSettings}.
   */
  @Slf4j
  public final static class Builder extends AbstractBuilder<CredentialSettings, Builder> {

    private Builder() {
    }

    /**
     * Assigns the default IdP credential.
     *
     * @param defaultCredential the default IdP credential
     * @return the builder
     */
    public Builder defaultCredential(final PkiCredential defaultCredential) {
      return this.setting(CredentialSettings.DEFAULT_CREDENTIAL, defaultCredential);
    }

    /**
     * Assigns the signing IdP credential.
     *
     * @param the signing credential
     * @return the builder
     */
    public Builder signCredential(final PkiCredential signCredential) {
      return this.setting(CredentialSettings.SIGN_CREDENTIAL, signCredential);
    }

    /**
     * Assigns the future IdP signing certificate. Assigned before a key-rollover is performed.
     *
     * @param the future signing certificate
     * @return the builder
     */
    public Builder futureSignCertificate(final X509Certificate futureSignCertificate) {
      return this.setting(CredentialSettings.FUTURE_SIGN_CERTIFICATE, futureSignCertificate);
    }

    /**
     * Assigns the encryption IdP credential.
     *
     * @param encryptCredential the encryption credential
     * @return the builder
     */
    public Builder encryptCredential(final PkiCredential encryptCredential) {
      return this.setting(CredentialSettings.ENCRYPT_CREDENTIAL, encryptCredential);
    }

    /**
     * Assigns the previous encryption IdP credential. Assigned after a key-rollover has been performed.
     *
     * @param previousEncryptCredential the previous encryption credential
     * @return the builder
     */
    public Builder previousEncryptCredential(final PkiCredential previousEncryptCredential) {
      return this.setting(CredentialSettings.PREVIOUS_ENCRYPT_CREDENTIAL,
          previousEncryptCredential);
    }

    /**
     * Gets the credential for signing metadata.
     *
     * @return the credential or null if none has been assigned
     */
    public Builder metadataSignCredential(final PkiCredential metadataSignCredential) {
      return this.setting(CredentialSettings.METADATA_SIGN_CREDENTIAL,
          metadataSignCredential);
    }

    /**
     * Builds the {@link CredentialSettings}.
     *
     * @return the {@link CredentialSettings}
     */
    @Override
    public CredentialSettings buildObject() {
      return new CredentialSettings(this.getSettings());
    }

    /** {@inheritDoc} */
    @Override
    protected void applyDefaultSettings() {
      if (!this.getSettings().containsValue(CredentialSettings.SIGN_CREDENTIAL)) {
        if (!this.getSettings().containsValue(CredentialSettings.DEFAULT_CREDENTIAL)) {
          log.warn("Using provided credential as default credential - Change this - DO NOT USE IN PRODUCTION");
          this.defaultCredential(this.loadDefaultCredential());
        }
      }
      if (!this.getSettings().containsValue(CredentialSettings.ENCRYPT_CREDENTIAL)) {
        if (!this.getSettings().containsValue(CredentialSettings.DEFAULT_CREDENTIAL)) {
          log.warn("Using provided credential as default credential - Change this - DO NOT USE IN PRODUCTION");
          this.defaultCredential(this.loadDefaultCredential());
        }
      }
    }

    private PkiCredential loadDefaultCredential() {
      final Resource jks = new ClassPathResource("idp-default-settings/default-credential.jks");
      final KeyStoreCredential defaultCredential =
          new KeyStoreCredential(jks, "secret".toCharArray(), "default", "secret".toCharArray());
      try {
        defaultCredential.afterPropertiesSet();
      }
      catch (final Exception e) {
        throw new SecurityException("Failed to to initialize default credentials", e);
      }
      return defaultCredential;
    }

  }
}
