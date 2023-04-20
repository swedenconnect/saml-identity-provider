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
package se.swedenconnect.spring.saml.idp.it;

import java.security.KeyStore;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;

import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.factory.KeyStoreFactoryBean;

@Configuration
public class CredentialConfiguration {

  @Bean("idp.credential.sign")
  PkiCredential signatureCredential(@Qualifier("idp.keystore") final KeyStore keyStore) {
    return new KeyStoreCredential(keyStore, "sign", "secret".toCharArray());
  }
  
  @Bean("idp.credential.encrypt")
  PkiCredential encryptionCredential(@Qualifier("idp.keystore") final KeyStore keyStore) {
    return new KeyStoreCredential(keyStore, "encrypt", "secret".toCharArray());
  }
  
  @Bean("idp.credential.metadata")
  PkiCredential metadataCredential(@Qualifier("idp.keystore") final KeyStore keyStore) {
    return new KeyStoreCredential(keyStore, "metadata", "secret".toCharArray());
  }
  
  @Bean("idp.keystore")
  KeyStoreFactoryBean idpKeystore() {
    return new KeyStoreFactoryBean(new ClassPathResource("idp-credentials.jks"), "secret".toCharArray(), "JKS"); 
  }
  
}
