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
package se.swedenconnect.spring.saml.idp.autoconfigure.settings;

import java.util.List;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.Assert;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;

/**
 * Main configuration properties class for the SAML Identity Provider.
 *
 * @author Martin Lindström
 */
@Data
@ConfigurationProperties("saml.idp")
@Slf4j
public class IdentityProviderConfigurationProperties implements InitializingBean {

  /**
   * The Identity Provider SAML entityID.
   */
  private String entityId;

  /**
   * The Identity Provider base URL, i.e., the protocol, domain and context path. Must not end with an '/'.
   */
  private String baseUrl;

  /**
   * The Identity Provider base URL for Holder-of-key support, i.e., the protocol, domain and context path. Must not end
   * with an '/'.
   * <p>
   * This setting is optional, and if HoK is being used <b>and</b> that requires a different IdP domain or context path
   * this setting represents this base URL.
   * </p>
   */
  private String hokBaseUrl;

  /**
   * Whether the IdP requires signed authentication requests.
   */
  private Boolean requiresSignedRequests;

  /**
   * The Identity Provider credentials.
   */
  private CredentialConfigurationProperties credentials;

  /**
   * The SAML IdP endpoints.
   */
  private EndpointsConfigurationProperties endpoints;
  
  /**
   * Assertion settings.
   */
  private AssertionSettingsConfigurationProperties assertions;

  /**
   * The IdP metadata.
   */
  private MetadataConfigurationProperties metadata;

  /**
   * The IdP metadata provider(s).
   */
  private List<MetadataProviderConfigurationProperties> metadataProviders;

  /** {@inheritDoc} */
  @Override
  public void afterPropertiesSet() throws Exception {
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
  }

}
