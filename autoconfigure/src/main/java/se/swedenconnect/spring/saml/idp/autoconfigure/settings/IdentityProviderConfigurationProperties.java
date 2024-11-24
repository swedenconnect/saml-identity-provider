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

import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.core.io.Resource;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import se.swedenconnect.security.credential.factory.PkiCredentialConfigurationProperties;
import se.swedenconnect.spring.saml.idp.settings.MetadataSettings;

import java.io.File;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * Main configuration properties class for the SAML Identity Provider.
 *
 * @author Martin Lindström
 */
@ConfigurationProperties("saml.idp")
@Slf4j
public class IdentityProviderConfigurationProperties implements InitializingBean {

  /**
   * The Identity Provider SAML entityID.
   */
  @Getter
  @Setter
  private String entityId;

  /**
   * The Identity Provider base URL, i.e., the protocol, domain and context path. Must not end with an '/'.
   */
  @Getter
  @Setter
  private String baseUrl;

  /**
   * The Identity Provider base URL for Holder-of-key support, i.e., the protocol, domain and context path. Must not end
   * with an '/'.
   * <p>
   * This setting is optional, and if HoK is being used <b>and</b> that requires a different IdP domain or context path
   * this setting represents this base URL.
   * </p>
   */
  @Getter
  @Setter
  private String hokBaseUrl;

  /**
   * Whether the IdP requires signed authentication requests.
   */
  @Getter
  @Setter
  private Boolean requiresSignedRequests;

  /**
   * Clock skew adjustment (in both directions) to consider for accepting messages based on their age.
   */
  @Getter
  @Setter
  private Duration clockSkewAdjustment;

  /**
   * Maximum allowed age of received messages.
   */
  @Getter
  @Setter
  private Duration maxMessageAge;

  /**
   * Based on a previous authentication, for how long may this authentication be re-used?
   */
  @Getter
  @Setter
  private Duration ssoDurationLimit;

  /**
   * Tells whether the IdP supports the <a
   * href="https://docs.swedenconnect.se/technical-framework/updates/18_-_User_Message_Extension_in_SAML_Authentication_Requests.html">User
   * Message Extension in SAML Authentication Requests"></a>.
   */
  @Getter
  @Setter
  private Boolean supportsUserMessage;

  /**
   * The Identity Provider credentials.
   */
  @Getter
  @Setter
  private CredentialConfigurationProperties credentials;

  /**
   * The SAML IdP endpoints.
   */
  @Getter
  @Setter
  private EndpointsConfigurationProperties endpoints;

  /**
   * Assertion settings.
   */
  @Getter
  @Setter
  private AssertionSettingsConfigurationProperties assertions;

  /**
   * The IdP metadata.
   */
  @Getter
  @Setter
  private MetadataConfigurationProperties metadata;

  /**
   * The IdP metadata provider(s).
   */
  @Getter
  @Setter
  private List<MetadataProviderConfigurationProperties> metadataProviders;

  /**
   * Configuration for replay checking.
   */
  @Getter
  @NestedConfigurationProperty
  private final ReplayCheckerConfigurationProperties replay = new ReplayCheckerConfigurationProperties();

  /**
   * Session configuration.
   */
  @Getter
  @NestedConfigurationProperty
  private final SessionConfiguration session = new SessionConfiguration();

  /** {@inheritDoc} */
  @Override
  public void afterPropertiesSet() throws IllegalArgumentException {
    Assert.hasText(this.entityId, "saml.idp.entity-id must be assigned");
    if (this.credentials == null) {
      log.debug("saml.idp.credentials.* is not assigned, assuming externally defined credential beans");
    }
    if (this.endpoints == null) {
      log.debug("saml.idp.endpoints.* is not assigned, will apply default values");
    }
    if (this.metadata == null) {
      log.debug("saml.idp.metadata.* is not assigned, will apply default values");
    }
    if (this.assertions == null) {
      log.debug("saml.idp.assertions.* is not assigned, will apply default values");
    }
    this.replay.afterPropertiesSet();
    this.session.afterPropertiesSet();
  }

  /**
   * Configuration properties for the IdP credentials.
   */
  public static class CredentialConfigurationProperties {

    /**
     * The IdP default credential.
     */
    @Setter
    @Getter
    private PkiCredentialConfigurationProperties defaultCredential;

    /**
     * The IdP signing credential.
     */
    @Setter
    @Getter
    private PkiCredentialConfigurationProperties sign;

    /**
     * A certificate that will be the future signing certificate. Is set before a key-rollover is performed.
     */
    @Setter
    @Getter
    private X509Certificate futureSign;

    /**
     * The IdP encryption credential.
     */
    @Setter
    @Getter
    private PkiCredentialConfigurationProperties encrypt;

    /**
     * The previous IdP encryption credential. Assigned after a key-rollover.
     */
    @Setter
    @Getter
    private PkiCredentialConfigurationProperties previousEncrypt;

    /**
     * The SAML metadata signing credential.
     */
    @Setter
    @Getter
    private PkiCredentialConfigurationProperties metadataSign;

  }

  /**
   * Configuration properties for endpoint configuration.
   */
  public static class EndpointsConfigurationProperties {

    /**
     * The endpoint where the Identity Provider receives authentication requests via HTTP redirect.
     */
    @Setter
    @Getter
    private String redirectAuthn;

    /**
     * The endpoint where the Identity Provider receives authentication requests via HTTP POST.
     */
    @Setter
    @Getter
    private String postAuthn;

    /**
     * The endpoint where the Identity Provider receives authentication requests via HTTP redirect where Holder-of-key
     * (HoK) is used.
     */
    @Setter
    @Getter
    private String hokRedirectAuthn;

    /**
     * The endpoint where the Identity Provider receives authentication requests via HTTP POST where Holder-of-key (HoK)
     * is used.
     */
    @Setter
    @Getter
    private String hokPostAuthn;

    /**
     * The SAML metadata publishing endpoint.
     */
    @Setter
    @Getter
    private String metadata;

  }

  /**
   * Session handling configuration.
   */
  public static class SessionConfiguration implements InitializingBean {

    /**
     * The session module to use. Supported values are "memory" and "redis". Set to other value if you extend the IdP
     * with your own session handling.
     */
    @Getter
    @Setter
    private String module;

    /** {@inheritDoc} */
    @Override
    public void afterPropertiesSet() {
    }

  }

  /**
   * For configuring the message replay checker.
   */
  public static class ReplayCheckerConfigurationProperties implements InitializingBean {

    /** The default expiration time for entries added to the cache. */
    public static final Duration DEFAULT_EXPIRATION = Duration.ofMinutes(5);

    /** The default context name to use for storing the cache. */
    public static final String DEFAULT_CONTEXT_NAME = "idp-replay-checker";

    /**
     * The type of replay checker. Supported values are "memory" and "redis".
     */
    @Getter
    @Setter
    private String type;

    /**
     * For how long should authentication request ID:s be stored in the cache before they expire?
     */
    @Getter
    @Setter
    private Duration expiration;

    /**
     * Under which context should the cache be stored? Applies to repositories that persist/distribute the cache.
     */
    @Getter
    @Setter
    private String context;

    /** {@inheritDoc} */
    @Override
    public void afterPropertiesSet() {
      if (this.expiration == null) {
        this.expiration = DEFAULT_EXPIRATION;
      }
      if (!StringUtils.hasText(this.context)) {
        this.context = DEFAULT_CONTEXT_NAME;
      }
    }

  }

  /**
   * Configuration properties for assertion settings.
   */
  public static class AssertionSettingsConfigurationProperties {

    /**
     * Tells whether the Identity Provider encrypts assertions.
     */
    @Getter
    @Setter
    private Boolean encrypt;

    /**
     * A setting that tells the time restrictions the IdP puts on an Assertion concerning "not on or after".
     */
    @Getter
    @Setter
    private Duration notAfter;

    /**
     * A setting that tells the time restrictions the IdP puts on an Assertion concerning "not before".
     */
    @Getter
    @Setter
    private Duration notBefore;

  }

  /**
   * Configuration properties for IdP metadata.
   */
  public static class MetadataConfigurationProperties {

    /**
     * A template for the IdP metadata.
     */
    @Setter
    @Getter
    private Resource template;

    /**
     * Tells how long the published IdP metadata can remain in a cache.
     */
    @Setter
    @Getter
    private Duration cacheDuration;

    /**
     * Tells for how long a published metadata entry should be valid.
     */
    @Setter
    @Getter
    private Duration validityPeriod;

    /**
     * The {@code alg:DigestMethod} elements to include in the metadata.
     */
    @Setter
    @Getter
    private List<String> digestMethods;

    /**
     * Whether {@code alg:DigestMethod} elements should be placed in an {@code Extensions} element under the role
     * descriptor (i.e., the {@code IDPSSODescriptor}). If {@code false}, the {@code alg:DigestMethod} elements are
     * included as elements in the {@code Extensions} element of the {@code EntityDescriptor}.
     */
    @Setter
    @Getter
    private boolean includeDigestMethodsUnderRole;

    /**
     * The {@code alg:SigningMethod} elements to include in the metadata.
     */
    @Setter
    @Getter
    private List<SigningMethod>
        signingMethods;

    /**
     * Whether {@code alg:SigningMethod} elements should be placed in an {@code Extensions} element under the role
     * descriptor (i.e., the {@code IDPSSODescriptor}). If {@code false}, the {@code alg:SigningMethod} elements are
     * included as elements in the {@code Extensions} element of the {@code EntityDescriptor}.
     */
    @Setter
    @Getter
    private boolean includeSigningMethodsUnderRole;

    /**
     * The {@code md:EncryptionMethod} elements that should be included under the {@code md:KeyDescriptor} for the
     * encryption key. Note that these algorithms must match the configured encryption key.
     */
    @Setter
    @Getter
    private List<EncryptionMethod> encryptionMethods;

    /**
     * The metadata {@code UIInfo} element.
     */
    @Setter
    @Getter
    private UIInfo uiInfo;

    /**
     * Attribute names that should be included under the {@code RequestedPrincipalSelection} metadata extension.
     */
    @Setter
    @Getter
    private List<String> requestedPrincipalSelection;

    /**
     * The metadata {@code Organization} element.
     */
    @Setter
    @Getter
    private Organization organization;

    /**
     * The metadata {@code ContactPerson} elements.
     */
    @Setter
    @Getter
    private Map<MetadataSettings.ContactPersonType, ContactPerson> contactPersons;

    /**
     * Settings for {@code alg:SigningMethod} elements.
     *
     * @author Martin Lindström
     */
    public static class SigningMethod {

      /**
       * Identifies the algorithm by means of the URL defined for its use with the XML Signature specification.
       */
      @Setter
      @Getter
      private String algorithm;

      /**
       * The smallest key size, in bits, that the entity supports in conjunction with the algorithm. If omitted, no
       * minimum is implied.
       */
      @Setter
      @Getter
      private Integer minKeySize;

      /**
       * The largest key size, in bits, that the entity supports in conjunction with the algorithm. If omitted, no
       * maximum is implied.
       */
      @Setter
      @Getter
      private Integer maxKeySize;
    }

    /**
     * Settings for {@code md:EncryptionMethod} elements.
     *
     * @author Martin Lindström
     */
    public static class EncryptionMethod {

      /**
       * The algorithm URI of the encryption method.
       */
      @Setter
      @Getter
      private String algorithm;

      /**
       * The key size.
       */
      @Setter
      @Getter
      private Integer keySize;

      /**
       * The OAEP parameters (in Base64-encoding).
       */
      @Setter
      @Getter
      private String oaepParams;

      /**
       * If {@code algorithm} indicates a key transport algorithm where the digest algorithm needs to be given, this
       * field should be set to this algorithm URI.
       */
      @Setter
      @Getter
      private String digestMethod;

    }

    /**
     * Settings for the metadata {@code UIInfo} element.
     */
    public static class UIInfo {

      /**
       * UIInfo display names. The map key is the language tag and value is display name for that language.
       */
      @Setter
      @Getter
      private Map<String, String> displayNames;

      /**
       * UIInfo descriptions. The map key is the language tag and value is description for that language.
       */
      @Setter
      @Getter
      private Map<String, String> descriptions;

      /**
       * UIInfo logotypes.
       */
      @Setter
      @Getter
      private List<UIInfo.Logo> logotypes;

      /**
       * Representation of a {@code Logo} element.
       */
      public static class Logo {

        /**
         * Logotype URL. Mutually exclusive with path.
         */
        @Setter
        @Getter
        private String url;

        /**
         * Logotype path. Mutually exclusive with url.
         */
        @Setter
        @Getter
        private String path;

        /**
         * Logotype height in pixels.
         */
        @Setter
        @Getter
        private Integer height;

        /**
         * Logotype width in pixels.
         */
        @Setter
        @Getter
        private Integer width;

        /**
         * Logotype language tag.
         */
        @Setter
        @Getter
        private String languageTag;
      }
    }

    /**
     * Settings for the {@code Organization} metadata element.
     */
    @Data
    public static class Organization {

      /**
       * The {@code OrganizationName}. The map key is the language tag and value is display name for that language.
       */
      private Map<String, String> names;

      /**
       * The {@code OrganizationDisplayName}. The map key is the language tag and value is display name for that
       * language.
       */
      private Map<String, String> displayNames;

      /**
       * The {@code OrganizationURL}. The map key is the language tag and value is display name for that language.
       */
      private Map<String, String> urls;
    }

    /**
     * Settings for the {@code ContactPerson} metadata element.
     */
    @Data
    public static class ContactPerson {

      /**
       * The {@code Company} element.
       */
      private String company;

      /**
       * The {@code GivenName} element.
       */
      private String givenName;

      /**
       * The {@code SurName} element.
       */
      private String surname;

      /**
       * The {@code EmailAddress} elements.
       */
      private List<String> emailAddresses;

      /**
       * The {@code TelephoneNumber} elements.
       */
      private List<String> telephoneNumbers;
    }

  }

  /**
   * Configuration properties for metadata provider configuration.
   */
  public static class MetadataProviderConfigurationProperties {

    /**
     * The location of the metadata. Can be a URL, a file, or even a classpath resource.
     */
    @Setter
    @Getter
    private Resource location;

    /**
     * If the {@code location} is an HTTPS resource, this setting may be used to specify a
     * <a href="https://spring.io/blog/2023/06/07/securing-spring-boot-applications-with-ssl">Spring SSL Bundle</a>
     * that gives the {@link javax.net.ssl.TrustManager}s to use during TLS verification. If no bundle is given, the
     * Java trust default will be used.
     */
    @Setter
    @Getter
    private String httpsTrustBundle;

    /**
     * If the {@code location} is an HTTPS resource, this setting tells whether to skip hostname verification in the TLS
     * connection (useful during testing).
     */
    @Setter
    @Getter
    private Boolean skipHostnameVerification;

    /**
     * If the {@code location} setting is a URL, a "backup location" may be assigned to store downloaded metadata.
     */
    @Setter
    @Getter
    private File backupLocation;

    /**
     * If the {@code location} setting is a URL, setting the MDQ-flag means that the metadata MDQ
     * (https://www.ietf.org/id/draft-young-md-query-17.html) protocol is used.
     */
    @Setter
    @Getter
    private Boolean mdq;

    /**
     * The certificate used to validate the metadata.
     */
    @Setter
    @Getter
    private X509Certificate validationCertificate;

    /**
     * If the {@code location} setting is a URL and an HTTP proxy is required this setting configures this proxy.
     */
    @Setter
    @Getter
    private HttpProxy httpProxy;

    /**
     * Configuration properties for an HTTP proxy.
     */
    public static class HttpProxy {

      /**
       * The proxy host.
       */
      @Setter
      @Getter
      private String host;

      /**
       * The proxy port.
       */
      @Setter
      @Getter
      private Integer port;

      /**
       * The proxy password (optional).
       */
      @Setter
      @Getter
      private String password;

      /**
       * The proxy username (optional).
       */
      @Setter
      @Getter
      private String userName;
    }

  }

}
