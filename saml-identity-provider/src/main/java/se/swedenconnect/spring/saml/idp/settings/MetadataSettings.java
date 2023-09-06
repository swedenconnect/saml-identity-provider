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

import java.time.Duration;
import java.util.List;
import java.util.Map;

import org.springframework.core.io.Resource;
import org.springframework.util.Assert;

import se.swedenconnect.spring.saml.idp.Saml2IdentityProviderVersion;

/**
 * Settings for the IdP metadata.
 *
 * @author Martin Lindström
 */
public class MetadataSettings extends AbstractSettings {

  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

  /**
   * Constructor.
   *
   * @param settings the settings
   */
  protected MetadataSettings(final Map<String, Object> settings) {
    super(settings);
  }

  /**
   * A template for the IdP metadata. A {@link Resource}.
   */
  public static final String SAML_METADATA_TEMPLATE = "template";

  /**
   * Gets the template for the IdP metadata.
   *
   * @return the template or {@code null} if not assigned.
   */
  public Resource getTemplate() {
    return this.getSetting(SAML_METADATA_TEMPLATE);
  }

  /**
   * Default cache duration.
   */
  public static final Duration SAML_METADATA_CACHE_DURATION_DEFAULT = Duration.ofHours(24);

  /**
   * Tells how long the published IdP metadata can remain in a cache. A {@link Duration}.
   */
  public static final String SAML_METADATA_CACHE_DURATION = "cache-duration";

  /**
   * Tells how long the published IdP metadata can remain in a cache.
   *
   * @return a {@link Duration}
   */
  public Duration getCacheDuration() {
    return this.getSetting(SAML_METADATA_CACHE_DURATION);
  }

  /**
   * Default metadata validity.
   */
  public static final Duration SAML_METADATA_VALIDITY_DEFAULT = Duration.ofDays(7);

  /**
   * Tells for how long a published metadata entry should be valid. A {@link Duration}.
   */
  public static final String SAML_METADATA_VALIDITY = "validity-period";

  /**
   * Tells for how long a published metadata entry should be valid.
   *
   * @return a {@link Duration}
   */
  public Duration getValidityPeriod() {
    return this.getSetting(SAML_METADATA_VALIDITY);
  }

  /**
   * The {@code alg:DigestMethod} elements that should be included in the metadata. A {@link List} of strings.
   */
  public static final String SAML_METADATA_DIGEST_METHODS = "digest-methods";

  /**
   * Gets the {@code alg:DigestMethod} elements that should be included in the metadata.
   *
   * @return a list of algorithms
   */
  public List<String> getDigestMethods() {
    return this.getSetting(SAML_METADATA_DIGEST_METHODS);
  }

  /**
   * Whether {@code alg:DigestMethod} elements should be placed in an {@code Extensions} element under the role
   * descriptor (i.e., the {@code IDPSSODescriptor}). If {@code false}, the {@code alg:DigestMethod} elements are
   * included as elements in the {@code Extensions} element of the {@code EntityDescriptor}. A {@link Boolean}.
   */
  public static final String SAML_METADATA_DIGEST_METHODS_UNDER_ROLE = "digest-methods-under-role";

  /**
   * Tells whether {@code alg:DigestMethod} elements should be placed in an {@code Extensions} element under the role
   * descriptor (i.e., the {@code IDPSSODescriptor}). If {@code false}, the {@code alg:DigestMethod} elements are
   * included as elements in the {@code Extensions} element of the {@code EntityDescriptor}.
   *
   * @return where to place elements
   */
  public Boolean getDigestMethodsUnderRole() {
    return this.getSetting(SAML_METADATA_DIGEST_METHODS_UNDER_ROLE);
  }

  /**
   * The {@code alg:SigningMethod} elements that should be included in the metadata. A {@link List} of
   * {@link SigningMethodSettings}.
   */
  public static final String SAML_METADATA_SIGNING_METHODS = "signing-methods";

  /**
   * Gets the {@code alg:SigningMethod} elements that should be included in the metadata.
   *
   * @return a list of signing methods
   */
  public List<SigningMethodSettings> getSigningMethods() {
    return this.getSetting(SAML_METADATA_SIGNING_METHODS);
  }

  /**
   * Whether {@code alg:SigningMethod} elements should be placed in an {@code Extensions} element under the role
   * descriptor (i.e., the {@code IDPSSODescriptor}). If {@code false}, the {@code alg:SigningMethod} elements are
   * included as elements in the {@code Extensions} element of the {@code EntityDescriptor}. A {@link Boolean}.
   */
  public static final String SAML_METADATA_SIGNING_METHODS_UNDER_ROLE = "signing-methods-under-role";

  /**
   * Tells whether {@code alg:SigningMethod} elements should be placed in an {@code Extensions} element under the role
   * descriptor (i.e., the {@code IDPSSODescriptor}). If {@code false}, the {@code alg:SigningMethod} elements are
   * included as elements in the {@code Extensions} element of the {@code EntityDescriptor}.
   *
   * @return where to place elements
   */
  public Boolean getSigningMethodsUnderRole() {
    return this.getSetting(SAML_METADATA_SIGNING_METHODS_UNDER_ROLE);
  }

  /**
   * The {@code md:EncryptionMethod} elements that should be included under the {@code md:KeyDescriptor} for the
   * encryption key. Note that these algorithms must match the configured encryption key. {@link List} of
   * {@link EncryptionMethodSettings}.
   */
  public static final String SAML_METADATA_ENCRYPTION_METHODS = "encryption-methods";

  /**
   * Gets the {@code md:EncryptionMethod} elements that should be included under the {@code md:KeyDescriptor} for the
   * encryption key. Note that these algorithms must match the configured encryption key.
   *
   * @return a list of {@link EncryptionMethodSettings}
   */
  public List<EncryptionMethodSettings> getEncryptionMethods() {
    return this.getSetting(SAML_METADATA_ENCRYPTION_METHODS);
  }

  /**
   * The {@code UIInfo} element. A {@link UIInfoSettings}.
   */
  public static final String SAML_METADATA_UI_INFO = "ui-info";

  /**
   * Gets the {@link UIInfoSettings}.
   *
   * @return {@link UIInfoSettings} or {@code null}
   */
  public UIInfoSettings getUiInfo() {
    return this.getSetting(SAML_METADATA_UI_INFO);
  }

  /**
   * Attribute names that should be included under the {@code RequestedPrincipalSelection} metadata extension. A
   * {@link List} of {@link String}s.
   */
  public static final String SAML_METADATA_REQUESTED_PRINCIPAL_SELECTION = "requested-principal-selection";

  /**
   * Gets the attribute names that should be included under the {@code RequestedPrincipalSelection} metadata extension.
   *
   * @return list of attribute names
   */
  public List<String> getRequestedPrincipalSelection() {
    return this.getSetting(SAML_METADATA_REQUESTED_PRINCIPAL_SELECTION);
  }

  /**
   * The {@code Organization} element. A {@link OrganizationSettings}.
   */
  public static final String SAML_METADATA_ORGANIZATION = "organization";

  /**
   * Gets the {@code Organization} element.
   *
   * @return a {@link OrganizationSettings} or {@code null}
   */
  public OrganizationSettings getOrganization() {
    return this.getSetting(SAML_METADATA_ORGANIZATION);
  }

  /**
   * A {@link Map} where the keys are {@link ContactPersonType} and the values {@link ContactPersonSettings}.
   */
  public static final String SAML_METADATA_CONTACT_PERSONS = "contact-persons";

  /**
   * Gets a {@link Map} where the keys are {@link ContactPersonType} and the values {@link ContactPersonSettings}.
   *
   * @return a map of contact persons
   */
  public Map<ContactPersonType, ContactPersonSettings> getContactPersons() {
    return this.getSetting(SAML_METADATA_CONTACT_PERSONS);
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
   * A builder for {@link MetadataSettings}.
   */
  public final static class Builder extends AbstractBuilder<MetadataSettings, Builder> {

    private Builder() {
    }

    /**
     * Assigns the template for the IdP metadata.
     *
     * @param template the metadata template
     * @return the builder
     */
    public Builder template(final Resource template) {
      return this.setting(SAML_METADATA_TEMPLATE, template);
    }

    /**
     * Assigns how long the published IdP metadata can remain in a cache.
     *
     * @param cacheDuration the cache duration
     * @return the builder
     */
    public Builder cacheDuration(final Duration cacheDuration) {
      return this.setting(SAML_METADATA_CACHE_DURATION, cacheDuration);
    }

    /**
     * Assigns for how long a published metadata entry should be valid.
     *
     * @param validityPeriod for how long a published metadata entry should be valid
     * @return the builder
     */
    public Builder validityPeriod(final Duration validityPeriod) {
      return this.setting(SAML_METADATA_VALIDITY, validityPeriod);
    }

    /**
     * Assigns the {@code alg:DigestMethod} elements that should be included in the metadata.
     *
     * @param digestMethods a list of algorithms
     * @return the builder
     */
    public Builder digestMethods(final List<String> digestMethods) {
      return this.setting(SAML_METADATA_DIGEST_METHODS, digestMethods);
    }

    /**
     * Assigns whether {@code alg:DigestMethod} elements should be placed in an {@code Extensions} element under the
     * role descriptor (i.e., the {@code IDPSSODescriptor}). If {@code false}, the {@code alg:DigestMethod} elements are
     * included as elements in the {@code Extensions} element of the {@code EntityDescriptor}.
     *
     * @param underRole assign under role
     * @return where to place elements
     */
    public Builder digestMethodsUnderRole(final Boolean underRole) {
      return this.setting(SAML_METADATA_DIGEST_METHODS_UNDER_ROLE, underRole);
    }

    /**
     * Assigns the {@code alg:SigningMethod} elements that should be included in the metadata.
     *
     * @param signingMethods the signing methods
     * @return a list of signing methods
     */
    public Builder signingMethods(final List<SigningMethodSettings> signingMethods) {
      return this.setting(SAML_METADATA_SIGNING_METHODS, signingMethods);
    }

    /**
     * Assigns whether {@code alg:SigningMethod} elements should be placed in an {@code Extensions} element under the
     * role descriptor (i.e., the {@code IDPSSODescriptor}). If {@code false}, the {@code alg:SigningMethod} elements
     * are included as elements in the {@code Extensions} element of the {@code EntityDescriptor}.
     *
     * @param underRole assign under role
     * @return where to place elements
     */
    public Builder signingMethodsUnderRole(final Boolean underRole) {
      return this.setting(SAML_METADATA_SIGNING_METHODS_UNDER_ROLE, underRole);
    }

    /**
     * Assigns the {@code md:EncryptionMethod} elements that should be included under the {@code md:KeyDescriptor} for
     * the encryption key. Note that these algorithms must match the configured encryption key.
     *
     * @param encryptionMethods a list of {@link EncryptionMethodSettings}
     * @return the builder
     */
    public Builder encryptionMethods(final List<EncryptionMethodSettings> encryptionMethods) {
      return this.setting(SAML_METADATA_ENCRYPTION_METHODS, encryptionMethods);
    }

    /**
     * Assigns the {@link UIInfoSettings}.
     *
     * @param uiInfo {@link UIInfoSettings}
     * @return the builder
     */
    public Builder uiInfo(final UIInfoSettings uiInfo) {
      return this.setting(SAML_METADATA_UI_INFO, uiInfo);
    }

    /**
     * Assigns the attribute names that should be included under the {@code RequestedPrincipalSelection} metadata extension.
     *
     * @param attributeNames list of attribute names
     * @return the builder
     */
    public Builder requestedPrincipalSelection(final List<String> attributeNames) {
      return this.setting(SAML_METADATA_REQUESTED_PRINCIPAL_SELECTION, attributeNames);
    }

    /**
     * Assigns the {@code Organization} element.
     *
     * @param organization an {@link OrganizationSettings}
     * @return the builder
     */
    public Builder organization(final OrganizationSettings organization) {
      return this.setting(SAML_METADATA_ORGANIZATION, organization);
    }

    /**
     * Assigns a {@link Map} where the keys are {@link ContactPersonType} and the values {@link ContactPersonSettings}.
     *
     * @param contactPersons a map of contact persons
     * @return the builder
     */
    public Builder contactPersons(final Map<ContactPersonType, ContactPersonSettings> contactPersons) {
      return this.setting(SAML_METADATA_CONTACT_PERSONS, contactPersons);
    }

    /** {@inheritDoc} */
    @Override
    protected void applyDefaultSettings() {
      if (this.getSettings().get(SAML_METADATA_CACHE_DURATION) == null) {
        this.cacheDuration(SAML_METADATA_CACHE_DURATION_DEFAULT);
      }
      if (this.getSettings().get(SAML_METADATA_VALIDITY) == null) {
        this.validityPeriod(SAML_METADATA_VALIDITY_DEFAULT);
      }
      if (this.getSettings().get(SAML_METADATA_DIGEST_METHODS_UNDER_ROLE) == null) {
        this.digestMethodsUnderRole(false);
      }
      if (this.getSettings().get(SAML_METADATA_SIGNING_METHODS_UNDER_ROLE) == null) {
        this.signingMethodsUnderRole(false);
      }
    }

    /** {@inheritDoc} */
    @Override
    protected MetadataSettings buildObject() {
      return new MetadataSettings(this.getSettings());
    }

  }

  /**
   * Configuration for SigningMethod metadata elements.
   *
   * @author Martin Lindström
   */
  public static class SigningMethodSettings extends AbstractSettings {

    private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

    /**
     * Constructor.
     *
     * @param settings the settings
     */
    protected SigningMethodSettings(final Map<String, Object> settings) {
      super(settings);
    }

    /**
     * Identifies the algorithm by means of the URL defined for its use with the XML Signature specification. A
     * {@link String}.
     */
    public static final String ALGORITHM = "algorithm";

    /**
     * Gets the signing algorithm.
     *
     * @return the signing algorithm
     */
    public String getAlgorithm() {
      return this.getSetting(ALGORITHM);
    }

    /**
     * The smallest key size, in bits, that the entity supports in conjunction with the algorithm. If omitted, no
     * minimum is implied. An {@link Integer}.
     */
    public static final String MIN_KEYSIZE = "min-keysize";

    /**
     * Gets the smallest key size, in bits, that the entity supports in conjunction with the algorithm.
     *
     * @return minimum key size
     */
    public Integer getMinKeySize() {
      return this.getSetting(MIN_KEYSIZE);
    }

    /**
     * The largest key size, in bits, that the entity supports in conjunction with the algorithm. If omitted, no maximum
     * is implied. An {@link Integer}.
     */
    public static final String MAX_KEYSIZE = "max-keysize";

    /**
     * Gets the largest key size, in bits, that the entity supports in conjunction with the algorithm.
     *
     * @return maximum key size
     */
    public Integer getMaxKeySize() {
      return this.getSetting(MAX_KEYSIZE);
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
     * A builder for {@link SigningMethodSettings}.
     */
    public final static class Builder extends AbstractBuilder<SigningMethodSettings, Builder> {

      private Builder() {
      }

      /**
       * Assigns the signing algorithm.
       *
       * @param algorithm the algorithm
       * @return the builder
       */
      public Builder algorithm(final String algorithm) {
        return this.setting(ALGORITHM, algorithm);
      }

      /**
       * Assigns the smallest key size, in bits, that the entity supports in conjunction with the algorithm.
       *
       * @param minKeySize minimum key size
       * @return the builder
       */
      public Builder minKeySize(final Integer minKeySize) {
        return this.setting(MIN_KEYSIZE, minKeySize);
      }

      /**
       * Assigns the largest key size, in bits, that the entity supports in conjunction with the algorithm.
       *
       * @param maxKeySize maximum key size
       * @return the builder
       */
      public Builder maxKeySize(final Integer maxKeySize) {
        return this.setting(MAX_KEYSIZE, maxKeySize);
      }

      /** {@inheritDoc} */
      @Override
      protected void applyDefaultSettings() {
      }

      /** {@inheritDoc} */
      @Override
      protected SigningMethodSettings buildObject() {
        return new SigningMethodSettings(this.getSettings());
      }
    }

  }

  /**
   * Configuration for EncryptionMethod metadata elements.
   *
   * @author Martin Lindström
   */
  public static class EncryptionMethodSettings extends AbstractSettings {

    private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

    /**
     * Constructor.
     *
     * @param settings the settings
     */
    protected EncryptionMethodSettings(final Map<String, Object> settings) {
      super(settings);
    }

    /**
     * The algorithm URI of the encryption method. A {@link String}.
     */
    public static final String ALGORITHM = "algorithm";

    /**
     * Gets the encryption algorithm.
     *
     * @return the encryption algorithm
     */
    public String getAlgorithm() {
      return this.getSetting(ALGORITHM);
    }

    /**
     * The key size, in bits, for the encryption algorithm. An {@link Integer}.
     */
    public static final String KEYSIZE = "keysize";

    /**
     * Gets the key size, in bits, for the algorithm.
     *
     * @return key size
     */
    public Integer getKeySize() {
      return this.getSetting(KEYSIZE);
    }

    /**
     * The OAEP params in base64 encoding. A {@link String}.
     */
    public static final String OAEP_PARAMS = "oaep-params";

    /**
     * Gets the OAEP params.
     *
     * @return the OAEP params
     */
    public String getOaepParams() {
      return this.getSetting(OAEP_PARAMS);
    }

    /**
     * If {@code algorithm} indicates a key transport algorithm where the digest algorithm needs to be given, this field
     * should be set to this algorithm URI. A {@link String}.
     */
    public static final String DIGEST_METHOD = "digest-method";

    /**
     * Gets the digest method URI. If {@code algorithm} indicates a key transport algorithm where the digest algorithm
     * needs to be given, this field should be set to this algorithm URI.
     *
     * @return URI
     */
    public String getDigestMethod() {
      return this.getSetting(DIGEST_METHOD);
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
     * A builder for {@link EncryptionMethodSettings}.
     */
    public final static class Builder extends AbstractBuilder<EncryptionMethodSettings, Builder> {

      private Builder() {
      }

      /**
       * Assigns the encryption algorithm.
       *
       * @param algorithm the algorithm
       * @return the builder
       */
      public Builder algorithm(final String algorithm) {
        return this.setting(ALGORITHM, algorithm);
      }

      /**
       * Assigns the key size.
       *
       * @param keySize key size
       * @return the builder
       */
      public Builder keySize(final Integer keySize) {
        return this.setting(KEYSIZE, keySize);
      }

      /**
       * Assigns the OAEP params.
       *
       * @param params the OAEP params
       * @return the builder
       */
      public Builder oaepParams(final String params) {
        return this.setting(OAEP_PARAMS, params);
      }

      /**
       * Assigns the digest method URI. If {@code algorithm} indicates a key transport algorithm where the digest
       * algorithm needs to be given, this field should be set to this algorithm URI.
       *
       * @param algorithm algorithm URI
       * @return the builder
       */
      public Builder digestMethod(final String algorithm) {
        return this.setting(DIGEST_METHOD, algorithm);
      }

      /** {@inheritDoc} */
      @Override
      protected void applyDefaultSettings() {
      }

      /** {@inheritDoc} */
      @Override
      protected EncryptionMethodSettings buildObject() {
        return new EncryptionMethodSettings(this.getSettings());
      }
    }

  }

  /**
   * Configuration for UIInfo metadata element.
   *
   * @author Martin Lindström
   */
  public static class UIInfoSettings extends AbstractSettings {

    private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

    /**
     * Constructor.
     *
     * @param settings the settings
     */
    protected UIInfoSettings(final Map<String, Object> settings) {
      super(settings);
    }

    /**
     * The UIInfo display name. A {@link Map}.
     */
    public static final String DISPLAY_NAME = "display-names";

    /**
     * Gets the UIInfo display names as a map of strings where the key is the language tag and the value is the display
     * name for that language.
     *
     * @return a map of display names
     */
    public Map<String, String> getDisplayNames() {
      return this.getSetting(DISPLAY_NAME);
    }

    /**
     * The UIInfo description. A {@link Map}.
     */
    public static final String DESCRIPTION = "descriptions";

    /**
     * Gets the UIInfo descriptions as a map of strings where the key is the language tag and the value is the
     * description for that language.
     *
     * @return a map of descriptions
     */
    public Map<String, String> getDescriptions() {
      return this.getSetting(DESCRIPTION);
    }

    /** The UIInfo logotypes. A {@link List} of {@link LogoSettings}. */
    public static final String LOGOTYPES = "logotypes";

    /**
     * Gets the UIInfo logotypes.
     *
     * @return the UIInfo logotypes.
     */
    public List<LogoSettings> getLogotypes() {
      return this.getSetting(LOGOTYPES);
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
     * A builder for {@link UIInfoSettings}.
     */
    public final static class Builder extends AbstractBuilder<UIInfoSettings, Builder> {

      private Builder() {
      }

      /**
       * Assigns the UIInfo display name as a map of strings where the key is the language tag and the value is the
       * display name for that language.
       *
       * @param displayName the display name
       * @return the builder
       */
      public Builder displayNames(final Map<String, String> displayName) {
        return this.setting(DISPLAY_NAME, displayName);
      }

      /**
       * Assigns the UIInfo description as a map of strings where the key is the language tag and the value is the
       * description for that language.
       *
       * @param description a map of descriptions
       * @return the builder
       */
      public Builder descriptions(final Map<String, String> description) {
        return this.setting(DESCRIPTION, description);
      }

      /**
       * Assigns the UIInfo logotypes.
       *
       * @param logotypes the UIInfo logotypes.
       * @return the builder
       */
      public Builder logotypes(final List<LogoSettings> logotypes) {
        return this.setting(LOGOTYPES, logotypes);
      }

      /** {@inheritDoc} */
      @Override
      protected void applyDefaultSettings() {
      }

      /** {@inheritDoc} */
      @Override
      protected UIInfoSettings buildObject() {
        return new UIInfoSettings(this.getSettings());
      }
    }

    /**
     * Configuration settings for {@code UIInfo.Logo} elements.
     *
     * @author Martin Lindström
     */
    public static class LogoSettings extends AbstractSettings {

      private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

      /**
       * Constructor.
       *
       * @param settings the settings
       */
      protected LogoSettings(final Map<String, Object> settings) {
        super(settings);
      }

      /** The logotype URL. Mutually exclusive with Path. A {@link String}. */
      public static final String URL = "url";

      /**
       * Gets the logotype URL. Mutually exclusive with Path.
       *
       * @return the URL
       */
      public String getUrl() {
        return this.getSetting(URL);
      }

      /** The logotype path. Mutually exclusive with URL. A {@link String}. */
      public static final String PATH = "path";

      /**
       * Gets the logotype path. Mutually exclusive with URL.
       *
       * @return the path
       */
      public String getPath() {
        return this.getSetting(PATH);
      }

      /** The height of the logo in pixels. An {@link Integer}. */
      public static final String HEIGHT = "height";

      /**
       * Gets the height of the logo in pixels.
       *
       * @return the logo height
       */
      public Integer getHeight() {
        return this.getSetting(HEIGHT);
      }

      /** The width of the logo in pixels. An {@link Integer}. */
      public static final String WIDTH = "width";

      /**
       * Gets the width of the logo in pixels.
       *
       * @return the logo width
       */
      public Integer getWidth() {
        return this.getSetting(WIDTH);
      }

      /** The logo language tag. A {@link String}. */
      public static final String LANGUAGE_TAG = "language-tag";

      /**
       * Gets the logo language tag.
       *
       * @return the logo language tag
       */
      public String getLanguageTag() {
        return this.getSetting(LANGUAGE_TAG);
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
       * A builder for {@link LogoSettings}.
       */
      public final static class Builder extends AbstractBuilder<LogoSettings, Builder> {

        private Builder() {
        }

        /**
         * Assigns the logotype URL.
         *
         * @param url the URL
         * @return the builder
         */
        public Builder url(final String url) {
          return this.setting(URL, url);
        }

        /**
         * Assigns the logotype path.
         *
         * @param path the path
         * @return the builder
         */
        public Builder path(final String path) {
          return this.setting(PATH, path);
        }

        /**
         * Assigns the height of the logo in pixels.
         *
         * @param height the logo height
         * @return the builder
         */
        public Builder height(final Integer height) {
          return this.setting(HEIGHT, height);
        }

        /**
         * Assigns the width of the logo in pixels.
         *
         * @param width the logo width
         * @return the builder
         */
        public Builder width(final Integer width) {
          return this.setting(WIDTH, width);
        }

        /**
         * Assigns the logo language tag.
         *
         * @param languageTag the language tag
         * @return the builder
         */
        public Builder languageTag(final String languageTag) {
          return this.setting(LANGUAGE_TAG, languageTag);
        }

        /** {@inheritDoc} */
        @Override
        protected void applyDefaultSettings() {
        }

        /** {@inheritDoc} */
        @Override
        protected LogoSettings buildObject() {
          return new LogoSettings(this.getSettings());
        }

      }

    }

  }

  /**
   * Configuration for Organization metadata element.
   *
   * @author Martin Lindström
   */
  public static class OrganizationSettings extends AbstractSettings {

    private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

    /**
     * Constructor.
     *
     * @param settings the settings
     */
    protected OrganizationSettings(final Map<String, Object> settings) {
      super(settings);
    }

    /**
     * The Organization name. A {@link Map}.
     */
    public static final String NAMES = "names";

    /**
     * Gets the Organization name as a map of strings where the key is the language tag and the value is the description
     * for that language.
     *
     * @return a map of names
     */
    public Map<String, String> getNames() {
      return this.getSetting(NAMES);
    }

    /**
     * The Organization display name. A {@link Map}.
     */
    public static final String DISPLAY_NAMES = "display-names";

    /**
     * Gets the Organization display names as a map of strings where the key is the language tag and the value is the
     * display name for that language.
     *
     * @return a map of display names
     */
    public Map<String, String> getDisplayNames() {
      return this.getSetting(DISPLAY_NAMES);
    }

    /**
     * The Organization URL:s. A {@link Map} where the key is the language tag and the URL the value.
     */
    public static final String URLS = "urls";

    /**
     * Gets the Organization URL:s as a map where the key is the language tag and the URL the value.
     *
     * @return a map of Organization URLs
     */
    public Map<String, String> getUrls() {
      return this.getSetting(URLS);
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
     * A builder for {@link OrganizationSettings}.
     */
    public final static class Builder extends AbstractBuilder<OrganizationSettings, Builder> {

      private Builder() {
      }

      /**
       * Assigns the Organization names as a map of strings where the key is the language tag and the value is the
       * description for that language.
       *
       * @param names a map of names
       * @return the builder
       */
      public Builder names(final Map<String, String> names) {
        return this.setting(NAMES, names);
      }

      /**
       * Assigns the Organization display name as a map of strings where the key is the language tag and the value is
       * the display name for that language.
       *
       * @param displayName the display name
       * @return the builder
       */
      public Builder displayNames(final Map<String, String> displayName) {
        return this.setting(DISPLAY_NAMES, displayName);
      }

      /**
       * Assigns the Organization URL:s as a map where the key is the language tag and the URL the value.
       *
       * @param urls a map of Organization URLs
       * @return the builder
       */
      public Builder urls(final Map<String, String> urls) {
        return this.setting(URLS, urls);
      }

      /** {@inheritDoc} */
      @Override
      protected void applyDefaultSettings() {
      }

      /** {@inheritDoc} */
      @Override
      protected OrganizationSettings buildObject() {
        return new OrganizationSettings(this.getSettings());
      }

    }

  }

  /**
   * ContactPerson types.
   */
  public enum ContactPersonType {
    technical, support, administrative, billing, other
  }

  /**
   * Configuration for ContactPerson metadata element.
   *
   * @author Martin Lindström
   */
  public static class ContactPersonSettings extends AbstractSettings {

    private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

    /**
     * Constructor.
     *
     * @param settings the settings
     */
    protected ContactPersonSettings(final Map<String, Object> settings) {
      super(settings);
    }

    /**
     * The {@code Company} element. A {@code String}.
     */
    public static final String COMPANY = "company";

    /**
     * Gets the {@code Company} element.
     *
     * @return the {@code Company}
     */
    public String getCompany() {
      return this.getSetting(COMPANY);
    }

    /**
     * The {@code GivenName} element. A {@code String}.
     */
    public static final String GIVEN_NAME = "given-name";

    /**
     * Gets the {@code GivenName} element.
     *
     * @return the {@code GivenName}
     */
    public String getGivenName() {
      return this.getSetting(GIVEN_NAME);
    }

    /**
     * The {@code SurName} element. A {@code String}.
     */
    public static final String SURNAME = "surname";

    /**
     * Gets the {@code SurName} element.
     *
     * @return the {@code SurName}
     */
    public String getSurname() {
      return this.getSetting(SURNAME);
    }

    /**
     * The {@code EmailAddress} elements. A {@link List} of {@link String}s.
     */
    public static final String EMAIL_ADDRESSES = "email-addresses";

    /**
     * Gets the {@code EmailAddress} elements.
     *
     * @return a list of the {@code EmailAddress}
     */
    public List<String> getEmailAddresses() {
      return this.getSetting(EMAIL_ADDRESSES);
    }

    /**
     * The {@code TelephoneNumber} elements. A {@link List} of {@link String}s.
     */
    public static final String TELEPHONE_NUMBERS = "telephone-numbers";

    /**
     * Gets the {@code TelephoneNumber} elements.
     *
     * @return a list of the {@code TelephoneNumber}s
     */
    public List<String> getTelephoneNumbers() {
      return this.getSetting(TELEPHONE_NUMBERS);
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
     * A builder for {@link OrganizationSettings}.
     */
    public final static class Builder extends AbstractBuilder<ContactPersonSettings, Builder> {

      private Builder() {
      }

      /**
       * Assigns the {@code Company} element.
       *
       * @param company the {@code Company}
       * @return the builder
       */
      public Builder company(final String company) {
        return this.setting(COMPANY, company);
      }

      /**
       * Assigns the {@code GivenName} element.
       *
       * @param givenName the {@code GivenName}
       * @return the builder
       */
      public Builder givenName(final String givenName) {
        return this.setting(GIVEN_NAME, givenName);
      }

      /**
       * Assigns the {@code SurName} element.
       *
       * @param surname the {@code SurName}
       * @return the builder
       */
      public Builder surname(final String surname) {
        return this.setting(SURNAME, surname);
      }

      /**
       * Assigns the {@code EmailAddress} elements.
       *
       * @param emailAddresses a list of the {@code EmailAddress}
       * @return the builder
       */
      public Builder emailAddresses(final List<String> emailAddresses) {
        return this.setting(EMAIL_ADDRESSES, emailAddresses);
      }

      /**
       * Assigns the {@code TelephoneNumber} elements.
       *
       * @param telephoneNumbers a list of the {@code TelephoneNumber}s
       * @return the builder
       */
      public Builder telephoneNumbers(final List<String> telephoneNumbers) {
        return this.setting(TELEPHONE_NUMBERS, telephoneNumbers);
      }

      /** {@inheritDoc} */
      @Override
      protected void applyDefaultSettings() {
      }

      /** {@inheritDoc} */
      @Override
      protected ContactPersonSettings buildObject() {
        return new ContactPersonSettings(this.getSettings());
      }
    }
  }

}
