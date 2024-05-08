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

import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.security.credential.factory.PkiCredentialConfigurationProperties;

import java.security.cert.X509Certificate;

/**
 * Configuration properties for the IdP credentials.
 * 
 * @author Martin Lindström
 */
public class CredentialConfigurationProperties {
    
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
