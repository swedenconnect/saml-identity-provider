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

import java.time.Duration;
import java.util.List;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

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
   * Tells whether the IdP supports the <a href="User Message Extension in SAML Authentication
   * Requests">https://docs.swedenconnect.se/technical-framework/updates/18_-_User_Message_Extension_in_SAML_Authentication_Requests.html</a>.
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

}
