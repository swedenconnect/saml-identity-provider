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

import java.util.ArrayList;
import java.util.List;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.redisson.Redisson;
import org.redisson.api.HostPortNatMapper;
import org.redisson.config.BaseConfig;
import org.redisson.config.ClusterServersConfig;
import org.redisson.config.Config;
import org.redisson.config.ReadMode;
import org.redisson.config.SingleServerConfig;
import org.redisson.spring.starter.RedissonAutoConfigurationCustomizer;
import org.redisson.spring.starter.RedissonAutoConfigurationV2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.data.redis.RedisProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.data.redis.core.RedisOperations;

import se.swedenconnect.spring.saml.idp.autoconfigure.redis.RedisTlsExtensionsConfiguration.SslBundleRegistrationBean;
import se.swedenconnect.spring.saml.idp.autoconfigure.redis.RedissonClusterProperties.NatTranslationEntry;

/**
 * For configuring Redisson extensions.
 *
 * @author Martin Lindström
 */
@ConditionalOnClass(RedissonAutoConfigurationV2.class)
@AutoConfiguration(before = RedissonAutoConfigurationV2.class)
@EnableConfigurationProperties({ RedisProperties.class, RedissonClusterProperties.class, ExtendedSslBundleProperties.class })
@Import({ RedisTlsExtensionsConfiguration.class, RedissonAutoConfigurationV2.class })
public class RedissonExtensionsAutoConfiguration {

  /** To ensure that the TLS extensions have been processed. */
  @Autowired
  SslBundleRegistrationBean _dummy;

  /** For accessing SslBundles. */
  @Autowired
  private SslBundles sslBundles;

  /** Spring Data Redis properties. */
  @Autowired
  private RedisProperties redisProperties;

  /** Extended SSL bundle properties. */
  @Autowired
  private ExtendedSslBundleProperties extBundleProperties;

  /** Redis cluster properties. */
  @Autowired
  private RedissonClusterProperties clusterProperties;

  /**
   * If Redisson is used, a {@link RedissonAutoConfigurationCustomizer} is created that configures the Redisson client
   * according to our extended Redis properties.
   *
   * @return a {@link RedissonAutoConfigurationCustomizer} bean
   */
  @ConditionalOnClass({ Redisson.class, RedisOperations.class })
  @Bean
  RedissonAutoConfigurationCustomizer redissonCustomizer() {
    return c -> {
      final BaseConfig<?> config = this.getRedissonConfiguration(c);
      if (this.redisProperties.getSsl().isEnabled()) {
        config.setSslEnableEndpointIdentification(this.extBundleProperties.isEnableClientHostnameVerification());
        final String bundle = this.redisProperties.getSsl().getBundle();
        if (bundle != null) {
          final SslBundle sslBundle = this.sslBundles.getBundle(bundle);
          config.setSslKeyManagerFactory(sslBundle.getManagers().getKeyManagerFactory());
          config.setSslTrustManagerFactory(sslBundle.getManagers().getTrustManagerFactory());
          if (sslBundle.getOptions().getCiphers() != null) {
            config.setSslCiphers(sslBundle.getOptions().getCiphers());
          }
        }
      }
    };
  }

  private BaseConfig<?> getRedissonConfiguration(final Config config) {
    if (config.isSingleConfig()) {
      return RedissonAddressCustomizers.singleServerSslCustomizer.apply(config.useSingleServer());
    }
    if (config.isClusterConfig()) {
      return RedissonAddressCustomizers.clusterServerCustomizer.apply(config.useClusterServers(),
          this.clusterProperties);
    }
    if (config.isSentinelConfig()) {
      throw new IllegalArgumentException("Sentinel Configuration is not implementend");
    }
    throw new IllegalStateException("Could not determine configuration type");
  }

  /**
   * Customizers to handle a bug where the protocol section of the address becomes non-TLS when TLS is enabled.
   *
   * @author Martin Lindström
   * @author Felix Hellman
   */
  private static class RedissonAddressCustomizers {

    public static BiFunction<ClusterServersConfig, RedissonClusterProperties, ClusterServersConfig> clusterServerCustomizer =
        (config, clusterProperties) -> {
          final List<String> addresses = new ArrayList<>();
          config.getNodeAddresses().forEach(address -> {
            String addr = address;
            if (address.contains("redis://")) {
              addr = address.replace("redis://", "rediss://");
            }
            addresses.add(addr);
          });
          config.setNodeAddresses(addresses);
          if (clusterProperties.getNatTranslation() != null) {
            final HostPortNatMapper mapper = new HostPortNatMapper();
            mapper.setHostsPortMap(clusterProperties.getNatTranslation().stream()
                .collect(Collectors.toMap(NatTranslationEntry::getFrom, NatTranslationEntry::getTo)));
            config.setNatMapper(mapper);
          }
          config.setReadMode(ReadMode.valueOf(clusterProperties.getReadMode()));
          return config;
        };

    public static Function<SingleServerConfig, SingleServerConfig> singleServerSslCustomizer = (s) -> {
      final String redisAddress = s.getAddress();
      if (redisAddress.contains("redis://")) {
        // The protocol part has not been configured by Spring even though we have enabled ssl
        s.setAddress(redisAddress.replace("redis://", "rediss://"));
      }
      return s;
    };

  }

}
