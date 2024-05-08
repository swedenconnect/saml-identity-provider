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
package se.swedenconnect.spring.saml.idp.settings;

import java.io.Serial;
import java.time.Duration;
import java.util.Map;

import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.springframework.util.Assert;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.spring.saml.idp.Saml2IdentityProviderVersion;

/**
 * Identity Provider configuration settings.
 *
 * @author Martin Lindström
 */
public class IdentityProviderSettings extends AbstractSettings {

  /** For serializing. */
  @Serial
  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

  /** Prefix for all configuration settings. */
  public static final String SETTINGS_PREFIX = "idp.";

  /**
   * Constructor.
   *
   * @param settings the settings
   */
  private IdentityProviderSettings(final Map<String, Object> settings) {
    super(settings);
  }

  /**
   * The Identity Provider entityID.
   */
  public static final String ENTITY_ID = SETTINGS_PREFIX.concat("entity-id");

  /**
   * Gets the SAML entityID of the Identity Provider.
   *
   * @return Identity Provider entityID
   */
  public String getEntityId() {
    return this.getSetting(ENTITY_ID);
  }

  /**
   * The Identity Provider base URL, i.e., the protocol, domain and context path. Must not end with an '/'.
   */
  public static final String BASE_URL = SETTINGS_PREFIX.concat("base-url");

  /**
   * Gets the Identity Provider base URL, i.e., the protocol, domain and context path. Must not end with an '/'.
   *
   * @return the IdP base URL
   */
  public String getBaseUrl() {
    return this.getSetting(BASE_URL);
  }

  /**
   * The Identity Provider base URL for Holder-of-key support, i.e., the protocol, domain and context path. Must not end
   * with an '/'.
   * <p>
   * This setting is optional, and if HoK is being used <b>and</b> that requires a different IdP domain or context path
   * this setting represents this base URL.
   * </p>
   */
  public static final String HOK_BASE_URL = SETTINGS_PREFIX.concat("hok-base-url");

  /**
   * Gets the Identity Provider base URL for Holder-of-key support, i.e., the protocol, domain and context path. Must
   * not end with an '/'.
   * <p>
   * This setting is optional, and if HoK is being used <b>and</b> that requires a different IdP domain or context path
   * this setting represents this base URL.
   * </p>
   *
   * @return the HoK base URL, or {@code null} if not assigned
   */
  public String getHokBaseUrl() {
    return this.getSetting(HOK_BASE_URL);
  }

  /**
   * Whether the IdP requires signed authentication requests. A {@link Boolean}.
   */
  public static final String REQUIRES_SIGNED_REQUESTS = SETTINGS_PREFIX.concat("requires-signed-requests");

  /**
   * Tells whether the IdP requires signed authentication requests.
   *
   * @return whether the IdP requires signed authentication requests
   */
  public Boolean getRequiresSignedRequests() {
    return this.getSetting(REQUIRES_SIGNED_REQUESTS);
  }

  /**
   * The default setting for the {@link #CLOCK_SKEW_ADJUSTMENT} setting.
   */
  public static final Duration CLOCK_SKEW_ADJUSTMENT_DEFAULT = Duration.ofSeconds(30);

  /**
   * Clock skew adjustment (in both directions) to consider still acceptable messages. A {@link Duration}.
   */
  public static final String CLOCK_SKEW_ADJUSTMENT = SETTINGS_PREFIX.concat("clock-skew-adjustment");

  /**
   * Gets the clock skew adjustment (in both directions) to consider still acceptable messages.
   * 
   * @return a {@link Duration}
   */
  public Duration getClockSkewAdjustment() {
    return this.getSetting(CLOCK_SKEW_ADJUSTMENT);
  }

  /**
   * The default setting for the {@link #MAX_MESSAGE_AGE} setting.
   */
  public static final Duration MAX_MESSAGE_AGE_DEFAULT = Duration.ofMinutes(3);

  /**
   * Maximum allowed age of received messages. A {@link Duration}.
   */
  public static final String MAX_MESSAGE_AGE = SETTINGS_PREFIX.concat("max-message-age");

  /**
   * Gets the maximum allowed age of received messages.
   * 
   * @return a {@link Duration}
   */
  public Duration getMaxMessageAge() {
    return this.getSetting(MAX_MESSAGE_AGE);
  }

  /**
   * The default value for the {@link #SSO_DURATION_LIMIT} setting.
   */
  public static final Duration SSO_DURATION_LIMIT_DEFAULT = Duration.ofHours(1);

  /**
   * Based on a previous authentication, for how long may this authentication be re-used? A {@link Duration}.
   */
  public static final String SSO_DURATION_LIMIT = SETTINGS_PREFIX.concat("sso-duration-limit");

  /**
   * Based on a previous authentication, for how long may this authentication be re-used?
   * 
   * @return a {@link Duration}
   */
  public Duration getSsoDurationLimit() {
    return this.getSetting(SSO_DURATION_LIMIT);
  }

  /**
   * The Identity Provider credentials.
   */
  public static final String IDP_CREDENTIALS = SETTINGS_PREFIX.concat("credentials");

  /**
   * Gets the IdP credentials.
   *
   * @return the IdP credentials
   */
  public CredentialSettings getCredentials() {
    return this.getSetting(IDP_CREDENTIALS);
  }

  /**
   * The Identity Provider endpoints.
   */
  public static final String IDP_ENDPOINTS = SETTINGS_PREFIX.concat("endpoints");

  /**
   * Gets the IdP endpoints settings.
   *
   * @return the IdP endpoints settings
   */
  public EndpointSettings getEndpoints() {
    return this.getSetting(IDP_ENDPOINTS);
  }

  /**
   * The Identity Provider Assertion settings.
   */
  public static final String IDP_ASSERTION_SETTINGS = SETTINGS_PREFIX.concat("assertion");

  /**
   * Gets the Identity Provider Assertion settings.
   * 
   * @return the Identity Provider Assertion settings
   */
  public AssertionSettings getAssertionSettings() {
    return this.getSetting(IDP_ASSERTION_SETTINGS);
  }

  /**
   * The Identity Provider metadata.
   */
  public static final String IDP_METADATA = SETTINGS_PREFIX.concat("metadata");

  /**
   * Gets the IdP metadata settings.
   *
   * @return the IdP metadata settings
   */
  public MetadataSettings getMetadata() {
    return this.getSetting(IDP_METADATA);
  }

  /**
   * The Identity Provider metadata provider (resolver). May be assigned if the {@link MetadataResolver} is created
   * "manually". See also {@link #IDP_METADATA_PROVIDER_CONFIGURATION} for an alternate way of configuring the metadata
   * provider.
   */
  public static final String IDP_METADATA_PROVIDER = "metadata-provider";

  /**
   * Gets the Identity Provider metadata provider (resolver).
   * <p>
   * A metadata provider may also be set up using {@link #IDP_METADATA_PROVIDER_CONFIGURATION}.
   * </p>
   * 
   * @return the metadata resolver to use or {@code null}
   * @see #getMetadataProviderConfiguration()
   */
  public MetadataResolver getMetadataProvider() {
    return this.getSetting(IDP_METADATA_PROVIDER);
  }

  /**
   * The Identity Provider metadata provider configuration. An array of {@link MetadataProviderSettings}. By using this
   * option instead of {@link #IDP_METADATA_PROVIDER} the application provides configuration for setting up a
   * {@link MetadataResolver}, but the actual creation is done by the configurers.
   */
  public static final String IDP_METADATA_PROVIDER_CONFIGURATION = SETTINGS_PREFIX.concat("metadata-provider-config");

  /**
   * Gets the IdP metadata provider configuration settings.
   * <p>
   * A metadata provider may also be set up using {@link #IDP_METADATA_PROVIDER}.
   * </p>
   * 
   * @return an array of metadata provider configuration settings
   * @see #getMetadataProvider()
   */
  public MetadataProviderSettings[] getMetadataProviderConfiguration() {
    return this.getSetting(IDP_METADATA_PROVIDER_CONFIGURATION);
  }

  /**
   * Constructs a new {@link Builder}.
   *
   * @return the builder
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
   * A builder for {@link IdentityProviderSettings}.
   */
  @Slf4j
  public final static class Builder extends AbstractBuilder<IdentityProviderSettings, Builder> {

    private Builder() {
    }

    /**
     * Assigns the SAML entityID of the Identity Provider.
     *
     * @param entityId the entityID
     * @return the builder
     */
    public Builder entityId(final String entityId) {
      return this.setting(ENTITY_ID, entityId);
    }

    /**
     * Assigns the Identity Provider base URL, i.e., the protocol, domain and context path. Must not end with an '/'.
     *
     * @param baseUrl the IdP base URL
     * @return the builder
     */
    public Builder baseUrl(final String baseUrl) {
      return this.setting(BASE_URL, baseUrl);
    }

    /**
     * Assigns the Identity Provider base URL for Holder-of-key support, i.e., the protocol, domain and context path.
     * Must not end with an '/'.
     * <p>
     * This setting is optional, and if HoK is being used <b>and</b> that requires a different IdP domain or context
     * path this setting represents this base URL.
     * </p>
     *
     * @param hokBaseUrl the HoK base URL
     * @return the builder
     */
    public Builder hokBaseUrl(final String hokBaseUrl) {
      return this.setting(HOK_BASE_URL, hokBaseUrl);
    }

    /**
     * Assigns whether the IdP requires signed authentication requests.
     *
     * @param requiresSignedRequests whether the IdP requires signed authentication requests
     * @return the builder
     */
    public Builder requiresSignedRequests(final Boolean requiresSignedRequests) {
      return this.setting(REQUIRES_SIGNED_REQUESTS, requiresSignedRequests);
    }

    /**
     * Assigns the clock skew adjustment (in both directions) to consider still acceptable messages.
     * 
     * @param clockSkewAdjustment a {@link Duration}
     * @return the builder
     */
    public Builder clockSkewAdjustment(final Duration clockSkewAdjustment) {
      return this.setting(CLOCK_SKEW_ADJUSTMENT, clockSkewAdjustment);
    }

    /**
     * Assigns the maximum allowed age of received messages.
     * 
     * @param maxMessageAge a {@link Duration}
     * @return the builder
     */
    public Builder maxMessageAge(final Duration maxMessageAge) {
      return this.setting(MAX_MESSAGE_AGE, maxMessageAge);
    }

    /**
     * Assigns for how long may this authentication be re-used.
     * 
     * @param ssoDurationLimit a {@link Duration}
     * @return the builder
     */
    public Builder ssoDurationLimit(final Duration ssoDurationLimit) {
      return this.setting(SSO_DURATION_LIMIT, ssoDurationLimit);
    }

    /**
     * Assigns the Identity Provider credentials.
     *
     * @param credentials the credentials
     * @return the builder
     */
    public Builder credentials(final CredentialSettings credentials) {
      return this.setting(IDP_CREDENTIALS, credentials);
    }

    /**
     * Assigns the IdP endpoints.
     *
     * @param endpoints the endpoints
     * @return the builder
     */
    public Builder endpoints(final EndpointSettings endpoints) {
      return this.setting(IDP_ENDPOINTS, endpoints);
    }

    /**
     * Assigns the Identity Provider Assertion settings.
     * 
     * @param assertionSettings the Identity Provider Assertion settings
     * @return the builder
     */
    public Builder assertionSettings(final AssertionSettings assertionSettings) {
      return this.setting(IDP_ASSERTION_SETTINGS, assertionSettings);
    }

    /**
     * Assigns the IdP metadata settings.
     *
     * @param metadata the IdP metadata settings
     * @return the builder
     */
    public Builder metadata(final MetadataSettings metadata) {
      return this.setting(IDP_METADATA, metadata);
    }

    /**
     * Assigns the Identity Provider metadata provider (resolver).
     * <p>
     * A metadata provider may also be set up using {@link #metadataProviderConfiguration(MetadataProviderSettings...)}.
     * </p>
     * 
     * @param metadataProvider the metadata resolver to use
     * @return the builder
     * @see #metadataProviderConfiguration(MetadataProviderSettings...)
     */
    public Builder metadataProvider(final MetadataResolver metadataProvider) {
      return this.setting(IDP_METADATA_PROVIDER, metadataProvider);
    }

    /**
     * Assigns the IdP metadata provider configuration settings.
     * <p>
     * A metadata provider may also be set up using {@link #metadataProvider(MetadataResolver)}.
     * </p>
     * 
     * @param metadataProviders an array of metadata provider configuration settings
     * @return the builder
     * @see #metadataProvider(MetadataResolver)
     */
    public Builder metadataProviderConfiguration(final MetadataProviderSettings... metadataProviders) {
      return this.setting(IDP_METADATA_PROVIDER_CONFIGURATION, metadataProviders);
    }

    /**
     * Builds the {@link IdentityProviderSettings}.
     *
     * @return the {@link IdentityProviderSettings}
     */
    @Override
    public IdentityProviderSettings buildObject() {
      return new IdentityProviderSettings(this.getSettings());
    }

    /** {@inheritDoc} */
    @Override
    protected void applyDefaultSettings() {
      if (this.getSettings().get(ENTITY_ID) == null) {
        final String baseUrl = (String) this.getSettings().get(BASE_URL);
        if (baseUrl != null) {
          log.warn("{} not assigned, defaulting to {}", ENTITY_ID, baseUrl);
          this.entityId(baseUrl);
        }
      }
      if (this.getSettings().get(REQUIRES_SIGNED_REQUESTS) == null) {
        this.requiresSignedRequests(Boolean.TRUE);
      }
      if (this.getSettings().get(CLOCK_SKEW_ADJUSTMENT) == null) {
        this.clockSkewAdjustment(CLOCK_SKEW_ADJUSTMENT_DEFAULT);
      }
      if (this.getSettings().get(MAX_MESSAGE_AGE) == null) {
        this.maxMessageAge(MAX_MESSAGE_AGE_DEFAULT);
      }
      if (this.getSettings().get(SSO_DURATION_LIMIT) == null) {
        this.ssoDurationLimit(SSO_DURATION_LIMIT_DEFAULT);
      }
      if (!this.getSettings().containsKey(IDP_CREDENTIALS)) {
        this.credentials(CredentialSettings.builder().build());
      }
      if (!this.getSettings().containsKey(IDP_ENDPOINTS)) {
        this.endpoints(EndpointSettings.builder().build());
      }
      if (!this.getSettings().containsKey(IDP_ASSERTION_SETTINGS)) {
        this.assertionSettings(AssertionSettings.builder().build());
      }
    }

  }

}
