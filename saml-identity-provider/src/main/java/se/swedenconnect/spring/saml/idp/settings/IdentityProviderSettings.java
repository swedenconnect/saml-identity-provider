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
package se.swedenconnect.spring.saml.idp.settings;

import java.util.Map;

import org.springframework.util.Assert;

import lombok.extern.slf4j.Slf4j;

/**
 * Identity Provider configuration settings.
 *
 * @author Martin Lindström
 */
public class IdentityProviderSettings extends AbstractSettings {

  /** For serializing. */
  private static final long serialVersionUID = 2388562287961752801L;

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
      return this.setting(IdentityProviderSettings.ENTITY_ID, entityId);
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
     * Assigns the Identity Provider base URL for Holder-of-key support, i.e., the protocol, domain and context path. Must
     * not end with an '/'.
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
     * Assigns the Identity Provider credentials.
     *
     * @param credentials the credentials
     * @return the builder
     */
    public Builder credentials(final CredentialSettings credentials) {
      return this.setting(IdentityProviderSettings.IDP_CREDENTIALS, credentials);
    }

    /**
     * Assigns the IdP endpoints.
     *
     * @param endpoints the endpoints
     * @return the builder
     */
    public Builder endpoints(final EndpointSettings endpoints) {
      return this.setting(IdentityProviderSettings.IDP_ENDPOINTS, endpoints);
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
      if (!this.getSettings().containsValue(ENTITY_ID)) {
        log.warn("Applying default setting for {} - Change this to your actual entityID", ENTITY_ID);
        this.entityId("https://demo.swedenconnect.se/idp");
      }
      if (!this.getSettings().containsValue(BASE_URL)) {
        log.warn("Applying default setting for {} - Change this to your actual base URL", BASE_URL);
        this.baseUrl("https://demo.swedenconnect.se/idp");
      }
      if (!this.getSettings().containsValue(REQUIRES_SIGNED_REQUESTS)) {
        this.requiresSignedRequests(Boolean.TRUE);
      }
      if (!this.getSettings().containsKey(IDP_CREDENTIALS)) {
        this.credentials(CredentialSettings.builder().build());
      }
      if (!this.getSettings().containsKey(IDP_ENDPOINTS)) {
        this.endpoints(EndpointSettings.builder().build());
      }
      if (!this.getSettings().containsKey(IDP_METADATA)) {
        this.metadata(MetadataSettings.builder().build());
      }
    }

  }

}
