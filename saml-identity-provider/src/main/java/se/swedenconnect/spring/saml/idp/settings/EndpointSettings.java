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

import java.util.Map;

import org.springframework.util.Assert;

import se.swedenconnect.spring.saml.idp.utils.Saml2IdentityProviderVersion;

/**
 * Settings for the IdP endpoints.
 *
 * @author Martin Lindström
 */
public class EndpointSettings extends AbstractSettings {

  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

  /**
   * Constructor.
   *
   * @param settings the settings
   */
  private EndpointSettings(final Map<String, Object> settings) {
    super(settings);
  }

  /**
   * The endpoint where the Identity Provider receives authentication requests via HTTP redirect.
   */
  public static final String SAML_REDIRECT_AUTHN_ENDPOINT = "redirect-authn";

  /**
   * Gets the endpoint where the Identity Provider receives authentication requests via HTTP redirect.
   *
   * @return the redirect authentication endpoint
   */
  public String getRedirectAuthnEndpoint() {
    return this.getSetting(SAML_REDIRECT_AUTHN_ENDPOINT);
  }

  /**
   * The endpoint where the Identity Provider receives authentication requests via HTTP POST.
   */
  public static final String SAML_POST_AUTHN_ENDPOINT = "post-authn";

  /**
   * Gets the endpoint where the Identity Provider receives authentication requests via HTTP POST.
   *
   * @return the POST authentication endpoint
   */
  public String getPostAuthnEndpoint() {
    return this.getSetting(SAML_POST_AUTHN_ENDPOINT);
  }

  /**
   * The endpoint where the Identity Provider receives authentication requests via HTTP redirect where Holder-of-key
   * (HoK) is used.
   */
  public static final String SAML_HOK_REDIRECT_AUTHN_ENDPOINT = "hok-redirect-authn";

  /**
   * Gets the endpoint where the Identity Provider receives authentication requests via HTTP redirect where Holder-of-key
   * (HoK) is used.
   *
   * @return the HoK redirect authentication endpoint
   */
  public String getHokRedirectAuthnEndpoint() {
    return this.getSetting(SAML_HOK_REDIRECT_AUTHN_ENDPOINT);
  }

  /**
   * The endpoint where the Identity Provider receives authentication requests via HTTP POST where Holder-of-key
   * (HoK) is used.
   */
  public static final String SAML_HOK_POST_AUTHN_ENDPOINT = "hok-post-authn";

  /**
   * Gets the endpoint where the Identity Provider receives authentication requests via HTTP POST where Holder-of-key
   * (HoK) is used.
   *
   * @return the HoK POST authentication endpoint
   */
  public String getHokPostAuthnEndpoint() {
    return this.getSetting(SAML_HOK_POST_AUTHN_ENDPOINT);
  }

  /**
   * The endpoint where the Identity Provider publishes its SAML metadata.
   */
  public static final String SAML_METADATA_PUBLISH_ENDPOINT = "metadata";

  /**
   * Gets the SAML metadata publishing endpoint.
   *
   * @return the endpoint
   */
  public String getMetadataEndpoint() {
    return this.getSetting(SAML_METADATA_PUBLISH_ENDPOINT);
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
   * A builder for {@link EndpointSettings}.
   */
  public final static class Builder extends AbstractBuilder<EndpointSettings, Builder> {

    private Builder() {
    }

    /**
     * Assigns the endpoint where the Identity Provider receives authentication requests via HTTP redirect.
     *
     * @param redirectAuthnEndpoint the redirect authentication endpoint
     * @return the builder
     */
    public Builder redirectAuthnEndpoint(final String redirectAuthnEndpoint) {
      return this.setting(SAML_REDIRECT_AUTHN_ENDPOINT, redirectAuthnEndpoint);
    }

    /**
     * Assigns the endpoint where the Identity Provider receives authentication requests via HTTP POST.
     *
     * @param postAuthnEndpoint the POST authentication endpoint
     * @return the builder
     */
    public Builder postAuthnEndpoint(final String postAuthnEndpoint) {
      return this.setting(SAML_POST_AUTHN_ENDPOINT, postAuthnEndpoint);
    }

    /**
     * Assigns the endpoint where the Identity Provider receives authentication requests via HTTP redirect
     * where Holder-of-key (HoK) is used.
     *
     * @param hokRedirectAuthnEndpoint the HoK redirect authentication endpoint
     * @return the builder
     */
    public Builder hokRedirectAuthnEndpoint(final String hokRedirectAuthnEndpoint) {
      return this.setting(SAML_HOK_REDIRECT_AUTHN_ENDPOINT, hokRedirectAuthnEndpoint);
    }

    /**
     * Assigns the endpoint where the Identity Provider receives authentication requests via HTTP POST
     * where Holder-of-key (HoK) is used.
     *
     * @param hokPostAuthnEndpoint the HoK POST authentication endpoint
     * @return the builder
     */
    public Builder hokPostAuthnEndpoint(final String hokPostAuthnEndpoint) {
      return this.setting(SAML_HOK_POST_AUTHN_ENDPOINT, hokPostAuthnEndpoint);
    }

    /**
     * Assigns the SAML metadata publishing endpoint.
     *
     * @param metadataEndpoint the endpoint
     * @return the builder
     */
    public Builder metadataEndpoint(final String metadataEndpoint) {
      return this.setting(SAML_METADATA_PUBLISH_ENDPOINT, metadataEndpoint);
    }

    /** {@inheritDoc} */
    @Override
    protected void applyDefaultSettings() {
      if (this.getSettings().get(SAML_REDIRECT_AUTHN_ENDPOINT) == null) {
        this.redirectAuthnEndpoint("/saml2/redirect/authn");
      }
      if (this.getSettings().get(SAML_POST_AUTHN_ENDPOINT) == null) {
        this.postAuthnEndpoint("/saml2/post/authn");
      }
      if (this.getSettings().get(SAML_METADATA_PUBLISH_ENDPOINT) == null) {
        this.metadataEndpoint("/saml2/metadata");
      }
    }

    /** {@inheritDoc} */
    @Override
    protected EndpointSettings buildObject() {
      return new EndpointSettings(this.getSettings());
    }
  }

}
