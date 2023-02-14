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
package se.swedenconnect.spring.saml.testsp.config;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

import lombok.Data;
import se.swedenconnect.security.credential.factory.PkiCredentialConfigurationProperties;

/**
 * Configuration properies for the SAML SP.
 *
 * @author Martin Lindström
 */
@ConfigurationProperties("saml.sp")
@Component
@Data
public class SamlSpConfigurationProperties {

  /**
   * The SAML SP entityID.
   */
  private String entityId;

  /**
   * The Spring Security SAML registration ID.
   */
  private String registrationId;
  
  /**
   * Location to IdP's metadata.
   */
  private Resource idpMetadataLocation;

  /**
   * The SAML SP credential.
   */
  private PkiCredentialConfigurationProperties credential;

  /**
   * The URL on which we receive SAML responses (assertions).
   */
  private String assertionConsumerUrl;

  /**
   * SAML SP metadata settings.
   */
  private Metadata metadata;

  @Data
  public static class Metadata {

    /**
     * The entity categories to include in the metadata extension.
     */
    private List<String> entityCategories;

    /**
     * Whether we want assertions to be signed.
     */
    private boolean wantAssertionsSigned;

  }

}
