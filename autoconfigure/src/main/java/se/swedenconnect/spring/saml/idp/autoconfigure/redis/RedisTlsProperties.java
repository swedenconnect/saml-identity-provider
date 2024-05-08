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
package se.swedenconnect.spring.saml.idp.autoconfigure.redis;

import java.security.KeyStore;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.DeprecatedConfigurationProperty;
import org.springframework.core.io.Resource;
import org.springframework.util.Assert;

import lombok.Getter;
import lombok.Setter;

/**
 * Spring Boot's Redis support does not enable us to configure SSL/TLS against the Redis server in a good way.
 * Therefore, we extend Spring's Redis configuration with this configuration properties class.
 *
 * @author Martin Lindström
 * @author Felix Hellman
 */
@ConfigurationProperties(prefix = "spring.data.redis.ssl-ext")
public class RedisTlsProperties implements InitializingBean {

  /**
   * Configuration for the KeyStore holding the Redis client SSL/TLS credential.
   */
  @Setter
  private KeyStoreConfiguration credential;

  /**
   * Should we verify the peer's hostname as part of the SSL/TLS handshake?
   */
  @Setter
  @Getter
  private boolean enableHostnameVerification = true;

  /**
   * To configure a specific trust for SSL/TLS we can supply a trust KeyStore.
   */
  @Setter
  private KeyStoreConfiguration trust;

  /**
   * Configuration for the KeyStore holding the Redis client SSL/TLS credential.
   *
   * @return keystore configuration
   */
  @DeprecatedConfigurationProperty(reason = "Use SslBundles instead")
  public KeyStoreConfiguration getCredential() {
    return this.credential;
  }

  /**
   * To configure a specific trust for SSL/TLS we can supply a trust KeyStore.
   * @return keystore configuration
   */
  @DeprecatedConfigurationProperty(reason = "Use SslBundles instead")
  public KeyStoreConfiguration getTrust() {
    return this.trust;
  }

  /** {@inheritDoc} */
  @Override
  public void afterPropertiesSet() throws IllegalArgumentException {
    if (this.credential != null) {
      Assert.notNull(this.credential.getResource(), "spring.redis.ssl-ext.credential.resource must be set");
      Assert.hasText(this.credential.getPassword(), "spring.redis.ssl-ext.credential.password must be set");
    }
    if (this.trust != null) {
      Assert.notNull(this.trust.getResource(), "spring.redis.ssl-ext.trust.resource must be set");
    }
  }

  /**
   * Configuration for a {@link KeyStore}.
   */
  public static class KeyStoreConfiguration {

    /**
     * The KeyStore resource.
     */
    @Getter
    @Setter
    private Resource resource;

    /**
     * The KeyStore password.
     */
    @Getter
    @Setter
    private String password;
  }

}
