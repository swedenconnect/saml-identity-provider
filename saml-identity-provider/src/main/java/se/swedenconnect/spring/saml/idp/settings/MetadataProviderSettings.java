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

import java.io.File;
import java.security.cert.X509Certificate;
import java.util.Map;

import org.springframework.core.io.Resource;
import org.springframework.util.Assert;

import se.swedenconnect.spring.saml.idp.Saml2IdentityProviderVersion;

/**
 * Settings for configuring SAML metadata providers (resolvers).
 * 
 * @author Martin Lindström
 */
public class MetadataProviderSettings extends AbstractSettings {

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
   * The location of the metadata. Can be an URL, a file, or even a classpath resource. Represented using a
   * {@link Resource}.
   */
  public static final String SAML_METADATA_PROVIDER_LOCATION = "location";

  /**
   * Gets the location of the metadata. Can be an URL, a file, or even a classpath resource.
   * 
   * @return the metadata location
   */
  public Resource getLocation() {
    return this.getSetting(SAML_METADATA_PROVIDER_LOCATION);
  }

  /**
   * If the {@code location} setting is an URL, a "backup location" may be assigned to store downloaded metadata. A
   * {@link File}.
   */
  public static final String SAML_METADATA_PROVIDER_BACKUP_LOCATION = "backup-location";

  /**
   * If the {@code location} setting is an URL, a "backup location" may be assigned to store downloaded metadata. This
   * method returns this file.
   * 
   * @return a file or {@code null}
   */
  public File getBackupLocation() {
    return this.getSetting(SAML_METADATA_PROVIDER_BACKUP_LOCATION);
  }

  /**
   * If the {@code location} setting is an URL, setting the MDQ-flag means that the metadata MDQ
   * (https://www.ietf.org/id/draft-young-md-query-17.html) protocol is used. A {@code Boolean}.
   */
  public static final String SAML_METADATA_PROVIDER_MDQ = "mdq";

  /**
   * If the {@code location} setting is an URL, setting the MDQ-flag means that the metadata MDQ
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
   * If the {@code location} setting is an URL and a HTTP proxy is required this setting configures this proxy. A
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
     * Assigns the location of the metadata. Can be an URL, a file, or even a classpath resource.
     * 
     * @param location the metadata location
     * @return the builder
     */
    public Builder location(final Resource location) {
      return this.setting(SAML_METADATA_PROVIDER_LOCATION, location);
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
     * @param mdq whether MDQ should be be used
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
      if (this.getSettings().get(SAML_METADATA_PROVIDER_MDQ) == null) {
        this.mdq(false);
      }
      // TODO: Default to Sweden Connect prod?
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
     * The HTTP proxy user name. A {@link String}.
     */
    public static final String HTTP_PROXY_USER_NAME = "user-name";

    /**
     * Gets the HTTP proxy user name.
     * 
     * @return the proxy user name or {@code null}
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
       * Assigns the HTTP proxy user name.
       * 
       * @param userName the proxy user name
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
