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
package se.swedenconnect.spring.saml.idp.settings;

import org.springframework.core.io.Resource;
import org.springframework.util.Assert;
import se.swedenconnect.spring.saml.idp.Saml2IdentityProviderVersion;

import java.io.File;
import java.io.Serial;
import java.security.cert.X509Certificate;
import java.util.Map;

/**
 * Settings for configuring SAML metadata providers (resolvers).
 *
 * @author Martin Lindström
 */
public class MetadataProviderSettings extends AbstractSettings {

  @Serial
  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

  /**
   * Constructor.
   *
   * @param settings the settings
   */
  protected MetadataProviderSettings(final Map<String, Object> settings) {
    super(settings);
  }

  /**
   * The location of the metadata. Can be a URL, a file, or even a classpath resource. Represented using a
   * {@link Resource}.
   */
  public static final String SAML_METADATA_PROVIDER_LOCATION = "location";

  /**
   * Gets the location of the metadata. Can be a URL, a file, or even a classpath resource.
   *
   * @return the metadata location
   */
  public Resource getLocation() {
    return this.getSetting(SAML_METADATA_PROVIDER_LOCATION);
  }

  /**
   * If the {@code location} is an HTTPS resource, this setting may be used to specify a
   * <a href="https://spring.io/blog/2023/06/07/securing-spring-boot-applications-with-ssl">Spring SSL Bundle</a> that
   * gives the {@link javax.net.ssl.TrustManager}s to use during TLS verification. If no bundle is given, the Java trust
   * default will be used.
   */
  public static final String SAML_METADATA_PROVIDER_HTTPS_TRUST_BUNDLE = "https-trust-bundle";

  /**
   * Gives the <a href="https://spring.io/blog/2023/06/07/securing-spring-boot-applications-with-ssl">Spring SSL
   * Bundle</a> that gives us the TLS trust settings to use during TLS verification. If {@code null}, the Java trust
   * default will be used.
   * <p>
   * Only relevant if the {@code location} is an HTTPS resource.
   * </p>
   *
   * @return a name for a trust SSL bundle, or {@code null} if not assigned
   */
  public String getHttpsTrustBundle() {
    return this.getSetting(SAML_METADATA_PROVIDER_HTTPS_TRUST_BUNDLE);
  }

  /**
   * If the {@code location} is an HTTPS resource, this setting tells whether to skip hostname verification in the TLS
   * connection (useful during testing).
   */
  public static final String SAML_METADATA_PROVIDER_SKIP_HOSTNAME_VERIFICATION = "skip-hostname-verification";

  /**
   * Tells whether to skip hostname verification in the TLS connection (useful during testing).
   *
   * @return {@code true} if hostname verification should be skipped
   */
  public Boolean getSkipHostnameVerification() {
    return this.getSetting(SAML_METADATA_PROVIDER_SKIP_HOSTNAME_VERIFICATION);
  }

  /**
   * If the {@code location} setting is a URL, a "backup location" may be assigned to store downloaded metadata. A
   * {@link File}.
   */
  public static final String SAML_METADATA_PROVIDER_BACKUP_LOCATION = "backup-location";

  /**
   * If the {@code location} setting is a URL, a "backup location" may be assigned to store downloaded metadata. This
   * method returns this file.
   *
   * @return a file or {@code null}
   */
  public File getBackupLocation() {
    return this.getSetting(SAML_METADATA_PROVIDER_BACKUP_LOCATION);
  }

  /**
   * If the {@code location} setting is a URL, setting the MDQ-flag means that the metadata MDQ
   * (https://www.ietf.org/id/draft-young-md-query-17.html) protocol is used. A {@code Boolean}.
   */
  public static final String SAML_METADATA_PROVIDER_MDQ = "mdq";

  /**
   * If the {@code location} setting is a URL, setting the MDQ-flag means that the metadata MDQ
   * (https://www.ietf.org/id/draft-young-md-query-17.html) protocol is used. This method returns this setting.
   *
   * @return whether MDQ is active or not
   */
  public Boolean getMdq() {
    return this.getSetting(SAML_METADATA_PROVIDER_MDQ);
  }

  /**
   * The certificate used to validate the metadata. A {@link X509Certificate}.
   */
  public static final String SAML_METADATA_PROVIDER_VALIDATION_CERTIFICATE = "validation-certificate";

  /**
   * Gets the certificate used to validate the metadata.
   *
   * @return the validation certificate or {@code null} if not assigned
   */
  public X509Certificate getValidationCertificate() {
    return this.getSetting(SAML_METADATA_PROVIDER_VALIDATION_CERTIFICATE);
  }

  /**
   * If the {@code location} setting is a URL and an HTTP proxy is required this setting configures this proxy. A
   * {@link HttpProxySettings}.
   */
  public static final String SAML_METADATA_PROVIDER_HTTP_PROXY = "http-proxy";

  /**
   * Gets the HTTP proxy settings.
   *
   * @return the proxy settings or {@code null}
   */
  public HttpProxySettings getHttpProxy() {
    return this.getSetting(SAML_METADATA_PROVIDER_HTTP_PROXY);
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
   * A builder for {@link MetadataProviderSettings}.
   */
  public final static class Builder extends AbstractBuilder<MetadataProviderSettings, Builder> {

    private Builder() {
    }

    /**
     * Assigns the location of the metadata. Can be a URL, a file, or even a classpath resource.
     *
     * @param location the metadata location
     * @return the builder
     */
    public Builder location(final Resource location) {
      return this.setting(SAML_METADATA_PROVIDER_LOCATION, location);
    }

    /**
     * Assigns the <a href="https://spring.io/blog/2023/06/07/securing-spring-boot-applications-with-ssl">Spring SSL
     * Bundle</a> that gives us the TLS trust settings to use during TLS verification. If not specified, the Java trust
     * default will be used.
     * <p>
     * Only relevant if the {@code location} is an HTTPS resource.
     * </p>
     *
     * @param httpsTrustBundle name for a trust SSL bundle
     * @return the builder
     */
    public Builder httpsTrustBundle(final String httpsTrustBundle) {
      return this.setting(SAML_METADATA_PROVIDER_HTTPS_TRUST_BUNDLE, httpsTrustBundle);
    }

    /**
     * Tells whether to skip hostname verification in the TLS connection (useful during testing).
     *
     * @param skip {@code true} if hostname verification should be skipped
     * @return the builder
     */
    public Builder skipHostnameVerification(final Boolean skip) {
      return this.setting(SAML_METADATA_PROVIDER_SKIP_HOSTNAME_VERIFICATION, skip);
    }

    /**
     * Assigns the backup file.
     * <p>
     * If the {@code location} setting is an URL, a "backup location" may be assigned to store downloaded metadata.
     * </p>
     *
     * @param backupLocation the backup location file
     * @return the builder
     */
    public Builder backupLocation(final File backupLocation) {
      return this.setting(SAML_METADATA_PROVIDER_BACKUP_LOCATION, backupLocation);
    }

    /**
     * Assigns whether MDQ should be used.
     * <p>
     * If the {@code location} setting is an URL, setting the MDQ-flag means that the metadata MDQ
     * (https://www.ietf.org/id/draft-young-md-query-17.html) protocol is used.
     * </p>
     *
     * @param mdq whether MDQ should be used
     * @return the builder
     */
    public Builder mdq(final Boolean mdq) {
      return this.setting(SAML_METADATA_PROVIDER_MDQ, mdq);
    }

    /**
     * Assigns the certificate used to validate the metadata.
     *
     * @param validationCertificate the validation certificate
     * @return the builder
     */
    public Builder validationCertificate(final X509Certificate validationCertificate) {
      return this.setting(SAML_METADATA_PROVIDER_VALIDATION_CERTIFICATE, validationCertificate);
    }

    /**
     * Assigns the HTTP proxy settings.
     *
     * @param httpProxy the proxy settings
     * @return the builder
     */
    public Builder httpProxy(final HttpProxySettings httpProxy) {
      return this.setting(SAML_METADATA_PROVIDER_HTTP_PROXY, httpProxy);
    }

    /** {@inheritDoc} */
    @Override
    protected void applyDefaultSettings() {
      if (this.getSettings().get(SAML_METADATA_PROVIDER_SKIP_HOSTNAME_VERIFICATION) == null) {
        this.skipHostnameVerification(Boolean.FALSE);
      }
      if (this.getSettings().get(SAML_METADATA_PROVIDER_MDQ) == null) {
        this.mdq(false);
      }
    }

    /** {@inheritDoc} */
    @Override
    protected MetadataProviderSettings buildObject() {
      return new MetadataProviderSettings(this.getSettings());
    }

  }

  /**
   * Settings for representing HTTP proxy configuration.
   *
   * @author Martin Lindström
   */
  public static class HttpProxySettings extends AbstractSettings {

    @Serial
    private static final long serialVersionUID = -2085596061776876139L;

    /**
     * Constructor.
     *
     * @param settings the settings
     */
    protected HttpProxySettings(final Map<String, Object> settings) {
      super(settings);
    }

    /**
     * The HTTP proxy host. A {@link String}.
     */
    public static final String HTTP_PROXY_HOST = "host";

    /**
     * Gets the HTTP proxy host.
     *
     * @return the HTTP proxy host
     */
    public String getHost() {
      return this.getSetting(HTTP_PROXY_HOST);
    }

    /**
     * The HTTP proxy port. An {@link Integer}.
     */
    public static final String HTTP_PROXY_PORT = "port";

    /**
     * Gets the HTTP proxy port.
     *
     * @return the HTTP proxy port
     */
    public Integer getPort() {
      return this.getSetting(HTTP_PROXY_PORT);
    }

    /**
     * The HTTP proxy username. A {@link String}.
     */
    public static final String HTTP_PROXY_USER_NAME = "user-name";

    /**
     * Gets the HTTP proxy username.
     *
     * @return the proxy username or {@code null}
     */
    public String getUserName() {
      return this.getSetting(HTTP_PROXY_USER_NAME);
    }

    /**
     * The HTTP proxy password. A {@link String}.
     */
    public static final String HTTP_PROXY_PASSWORD = "password";

    /**
     * Gets the HTTP proxy password.
     *
     * @return the HTTP proxy password or {@code null}
     */
    public String getPassword() {
      return this.getSetting(HTTP_PROXY_PASSWORD);
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
     * A builder for {@link HttpProxySettings}.
     */
    public final static class Builder extends AbstractBuilder<HttpProxySettings, Builder> {

      private Builder() {
      }

      /**
       * Assigns the HTTP proxy host.
       *
       * @param host the HTTP proxy host
       * @return the builder
       */
      public Builder host(final String host) {
        return this.setting(HTTP_PROXY_HOST, host);
      }

      /**
       * Assigns the HTTP proxy port.
       *
       * @param port the HTTP proxy port
       * @return the builder
       */
      public Builder port(final Integer port) {
        return this.setting(HTTP_PROXY_PORT, port);
      }

      /**
       * Assigns the HTTP proxy username.
       *
       * @param userName the proxy username
       * @return the builder
       */
      public Builder userName(final String userName) {
        return this.setting(HTTP_PROXY_USER_NAME, userName);
      }

      /**
       * Assigns the HTTP proxy password.
       *
       * @param password the HTTP proxy password
       * @return the builder
       */
      public Builder password(final String password) {
        return this.setting(HTTP_PROXY_PASSWORD, password);
      }

      /** {@inheritDoc} */
      @Override
      protected void applyDefaultSettings() {
      }

      /** {@inheritDoc} */
      @Override
      protected HttpProxySettings buildObject() {
        return new HttpProxySettings(this.getSettings());
      }

    }

  }

}
