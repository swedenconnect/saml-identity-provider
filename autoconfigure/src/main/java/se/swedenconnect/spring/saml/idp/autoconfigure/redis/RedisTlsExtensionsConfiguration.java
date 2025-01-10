/*
 * Copyright 2023-2025 Sweden Connect
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

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.data.redis.RedisProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundleKey;
import org.springframework.boot.ssl.SslBundleRegistry;
import org.springframework.boot.ssl.SslManagerBundle;
import org.springframework.boot.ssl.SslOptions;
import org.springframework.boot.ssl.SslStoreBundle;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.Optional;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.UUID;
import java.util.stream.StreamSupport;

/**
 * Configuration class that transforms the deprecated {@link RedisTlsProperties} to a {@link SslBundle}.
 *
 * @author Martin Lindström
 */
@Configuration
@EnableConfigurationProperties({ RedisProperties.class, RedisTlsProperties.class })
@Slf4j
public class RedisTlsExtensionsConfiguration {

  /** For registering SslBundles (needed to support the old way of handling Redis TLs properties). */
  private final SslBundleRegistry sslBundleRegistry;

  /** The Redis properties. */
  private final RedisProperties redisProperties;

  /** The extended Redis TLS properties. */
  private final RedisTlsProperties tlsProperties;

  /**
   * Constructor.
   *
   * @param redisProperties the Redis properties
   * @param tlsProperties the extended Redis TLS properties
   * @param sslBundleRegistry for registering SslBundles
   */
  public RedisTlsExtensionsConfiguration(final RedisProperties redisProperties,
      final RedisTlsProperties tlsProperties, final SslBundleRegistry sslBundleRegistry) {
    this.redisProperties = redisProperties;
    this.tlsProperties = tlsProperties;
    this.sslBundleRegistry = sslBundleRegistry;
  }

  /**
   * Creates a {@link SslBundleRegistrationBean} that registers a {@link SslBundle} and updates the
   * {@link RedisProperties} if the settings of {@link RedisTlsProperties} are assigned.
   *
   * @return a SslBundleRegistrationBean
   * @throws Exception for KeyStore errors
   */
  @Bean
  SslBundleRegistrationBean sslBundleRegistrationBean() throws Exception {
    return new SslBundleRegistrationBean(this.redisProperties, this.tlsProperties, this.sslBundleRegistry);
  }

  /**
   * For registering a SslBunde based on TLS extension properties.
   */
  public static class SslBundleRegistrationBean {

    public SslBundleRegistrationBean(final RedisProperties redisProperties,
        final RedisTlsProperties tlsProperties, final SslBundleRegistry sslBundleRegistry) throws Exception {

      // If a bundle is configured, we use that ...
      //
      if (redisProperties.getSsl().getBundle() != null) {
        return;
      }

      if (tlsProperties.getCredential() == null && tlsProperties.getTrust() == null) {
        return;
      }

      final SslBundleKey sslBundleKey;
      final KeyStore keyStore;
      final String keyStorePassword;
      final KeyStore trustStore;

      if (tlsProperties.getCredential() != null) {

        keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStorePassword = tlsProperties.getCredential().getPassword();

        try (final InputStream is = tlsProperties.getCredential().getResource().getInputStream()) {
          keyStore.load(is, keyStorePassword.toCharArray());
        }
        final String alias = StreamSupport.stream(
                Spliterators.spliteratorUnknownSize(keyStore.aliases().asIterator(), Spliterator.ORDERED), false)
            .filter(a -> {
              try {
                return keyStore.isKeyEntry(a);
              }
              catch (final KeyStoreException e) {
                return false;
              }
            })
            .findFirst()
            .orElseThrow(() -> new SecurityException("No valid alias found"));

        sslBundleKey = SslBundleKey.of(tlsProperties.getCredential().getPassword(), alias);
      }
      else {
        sslBundleKey = SslBundleKey.NONE;
        keyStore = null;
        keyStorePassword = null;
      }
      if (tlsProperties.getTrust() != null) {
        trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        try (final InputStream is = tlsProperties.getTrust().getResource().getInputStream()) {
          final char[] password = Optional.ofNullable(tlsProperties.getTrust().getPassword())
              .map(String::toCharArray)
              .orElseGet(() -> new char[0]);
          trustStore.load(is, password);
        }
      }
      else {
        trustStore = null;
      }

      final SslBundle sslBundle = new SslBundle() {

        @Override
        public SslStoreBundle getStores() {
          return SslStoreBundle.of(keyStore, keyStorePassword, trustStore);
        }

        @Override
        public String getProtocol() {
          return SslBundle.DEFAULT_PROTOCOL;
        }

        @Override
        public SslOptions getOptions() {
          return SslOptions.NONE;
        }

        @Override
        public SslManagerBundle getManagers() {
          return SslManagerBundle.from(this.getStores(), this.getKey());
        }

        @Override
        public SslBundleKey getKey() {
          return sslBundleKey;
        }
      };

      final String bundleName = UUID.randomUUID().toString();

      log.info("Registering SslBunde '{}' to hold settings from spring.data.redis.ssl-ext.*", bundleName);
      sslBundleRegistry.registerBundle(bundleName, sslBundle);

      redisProperties.getSsl().setBundle(bundleName);
    }
  }

}
