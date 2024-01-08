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

import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.data.redis.JedisClientConfigurationBuilderCustomizer;
import org.springframework.boot.autoconfigure.data.redis.LettuceClientConfigurationBuilderCustomizer;
import org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration;
import org.springframework.boot.autoconfigure.data.redis.RedisProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.data.redis.core.RedisOperations;

import se.swedenconnect.spring.saml.idp.autoconfigure.redis.RedisTlsExtensionsConfiguration.SslBundleRegistrationBean;

/**
 * Auto configuration for Redis extensions.
 *
 * @author Martin Lindström
 */
@AutoConfiguration(before = RedisAutoConfiguration.class)
@ConditionalOnClass(RedisOperations.class)
@EnableConfigurationProperties({ RedisProperties.class, ExtendedSslBundleProperties.class })
@Import({ RedisTlsExtensionsConfiguration.class, RedisAutoConfiguration.class })
public class RedisExtensionsAutoConfiguration {

  /** To ensure that the TLS extensions have been processed. */
  @Autowired
  SslBundleRegistrationBean _dummy;

  /** Spring Data Redis properties. */
  @Autowired
  private RedisProperties redisProperties;

  /** Extended SSL bundle properties. */
  @Autowired
  private ExtendedSslBundleProperties extBundleProperties;

  /**
   * If Jedis is available, a {@link JedisClientConfigurationBuilderCustomizer} is created that configures the Jedis
   * client according to our extended Redis properties.
   *
   * @return a {@link JedisClientConfigurationBuilderCustomizer} bean
   */
  @ConditionalOnClass
  @Bean
  JedisClientConfigurationBuilderCustomizer jedisCustomizer() {
    return c -> {
      if (this.redisProperties.getSsl().isEnabled()) {
        if (!this.extBundleProperties.isEnableClientHostnameVerification()) {
          c.useSsl().hostnameVerifier(NoopHostnameVerifier.INSTANCE);
        }
      }
    };
  }

  /**
   * If Lettuce is available, a {@link LettuceClientConfigurationBuilderCustomizer} is created that configures the
   * Lettuce client according to our extended Redis properties.
   *
   * @return a {@link LettuceClientConfigurationBuilderCustomizer} bean
   */
  @ConditionalOnClass
  @Bean
  LettuceClientConfigurationBuilderCustomizer lettuceCustomizer() {
    return c -> {
      if (this.redisProperties.getSsl().isEnabled()) {
        if (!this.extBundleProperties.isEnableClientHostnameVerification()) {
          c.useSsl().disablePeerVerification();
        }
      }
    };
  }

}
