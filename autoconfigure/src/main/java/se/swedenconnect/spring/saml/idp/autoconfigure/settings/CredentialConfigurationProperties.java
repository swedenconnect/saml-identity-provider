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

import java.security.cert.X509Certificate;

import lombok.Data;
import se.swedenconnect.security.credential.factory.PkiCredentialConfigurationProperties;

/**
 * Configuration properties for the IdP credentials.
 * 
 * @author Martin Lindström
 */
@Data
public class CredentialConfigurationProperties {
    
  /**
   * The IdP default credential.
   */
  private PkiCredentialConfigurationProperties defaultCredential;

  /**
   * The IdP signing credential.
   */
  private PkiCredentialConfigurationProperties sign;

  /**
   * A certificate that will be the future signing certificate. Is set before a key-rollover is performed.
   */
  private X509Certificate futureSign;

  /**
   * The IdP encryption credential.
   */
  private PkiCredentialConfigurationProperties encrypt;
  
  /**
   * The previous IdP encryption credential. Assigned after a key-rollover.
   */
  private PkiCredentialConfigurationProperties previousEncrypt;
  
  /**
   * The SAML metadata signing credential.
   */
  private PkiCredentialConfigurationProperties metadataSign;
  
}
