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
package se.swedenconnect.spring.saml.idp.autoconfigure.settings;

import org.opensaml.storage.ReplayCache;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.data.redis.core.StringRedisTemplate;
import se.swedenconnect.opensaml.saml2.response.replay.MessageReplayChecker;
import se.swedenconnect.opensaml.saml2.response.replay.MessageReplayCheckerImpl;
import se.swedenconnect.spring.saml.idp.authnrequest.validation.replay.InMemoryReplayCache;
import se.swedenconnect.spring.saml.idp.authnrequest.validation.replay.RedisReplayCache;

/**
 * Autoconfiguration for setting up a {@link MessageReplayChecker} bean.
 *
 * @author Martin Lindström
 */
@ConditionalOnMissingBean(MessageReplayChecker.class)
@AutoConfiguration(before = IdentityProviderAutoConfiguration.class)
@EnableConfigurationProperties(IdentityProviderConfigurationProperties.class)
@Import(MessageReplayCheckerAutoConfiguration.RedisMessageReplayCheckerConfiguration.class)
public class MessageReplayCheckerAutoConfiguration {

  /** The configuration properties. */
  private final IdentityProviderConfigurationProperties properties;

  /**
   * Constructor.
   *
   * @param properties the configuration properties
   */
  public MessageReplayCheckerAutoConfiguration(final IdentityProviderConfigurationProperties properties) {
    this.properties = properties;
  }

  /**
   * Creates an in-memory {@link ReplayCache} bean.
   *
   * @return a {@link ReplayCache}
   */
  @ConditionalOnMissingBean
  @ConditionalOnProperty(value = "saml.idp.replay.type", havingValue = "memory", matchIfMissing = true)
  @Bean
  ReplayCache inMemoryReplayCache() {
    return new InMemoryReplayCache();
  }

  /**
   * Creates a {@link MessageReplayChecker} bean.
   *
   * @param replayCache the {@link ReplayCache}
   * @return a {@link MessageReplayChecker} bean
   */
  @Bean
  MessageReplayChecker messageReplayChecker(final ReplayCache replayCache) {
    final MessageReplayCheckerImpl checker =
        new MessageReplayCheckerImpl(replayCache, this.properties.getReplay().getContext());
    checker.setReplayCacheExpiration(this.properties.getReplay().getExpiration().toMillis());
    return checker;
  }

  /**
   * For configuration of a {@link RedisReplayCache} bean.
   */
  @ConditionalOnProperty(value = "saml.idp.replay.type", havingValue = "redis", matchIfMissing = true)
  @ConditionalOnBean(StringRedisTemplate.class)
  @Configuration
  public static class RedisMessageReplayCheckerConfiguration {

    /**
     * If we are using Redis, we create a {@link RedisReplayCache}
     *
     * @param redisTemplate the Redis template
     * @return a {@link RedisReplayCache}
     */
    @ConditionalOnMissingBean
    @Bean
    ReplayCache redisReplayCache(final StringRedisTemplate redisTemplate) {
      return new RedisReplayCache(redisTemplate);
    }

  }

}
