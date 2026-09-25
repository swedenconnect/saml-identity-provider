/*
 * Copyright 2023-2026 Sweden Connect
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

import java.util.Optional;

import org.opensaml.storage.ReplayCache;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.util.StringUtils;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.opensaml.saml2.response.replay.MessageReplayChecker;
import se.swedenconnect.opensaml.saml2.response.replay.MessageReplayCheckerImpl;
import se.swedenconnect.spring.saml.idp.authnrequest.validation.replay.InMemoryReplayCache;
import se.swedenconnect.spring.saml.idp.authnrequest.validation.replay.RedisReplayCache;

/**
 * Autoconfiguration for setting up a {@link MessageReplayChecker} bean.
 * <p>
 * The {@link ReplayCache} to use is given by the {@code saml.idp.replay.type} property. If this property is not set, a
 * {@link RedisReplayCache} is used if a {@link StringRedisTemplate} bean is available, otherwise an
 * {@link InMemoryReplayCache} is used. If the property is set to {@code redis} and no {@link StringRedisTemplate} bean
 * is available, or if it is set to an unknown value, the application will fail to start.
 * </p>
 *
 * @author Martin Lindström
 */
@Slf4j
@ConditionalOnMissingBean(MessageReplayChecker.class)
@AutoConfiguration(before = IdentityProviderAutoConfiguration.class,
    // Spring Boot's Redis autoconfiguration, which declares the StringRedisTemplate bean, must have been applied
    // before this autoconfiguration. Given by name, since Redis is not necessarily on the classpath.
    afterName = "org.springframework.boot.data.redis.autoconfigure.DataRedisAutoConfiguration")
@EnableConfigurationProperties(IdentityProviderConfigurationProperties.class)
@Import(MessageReplayCheckerAutoConfiguration.RedisMessageReplayCheckerConfiguration.class)
public class MessageReplayCheckerAutoConfiguration {

  /** The property that tells which type of replay cache to use. */
  private static final String TYPE_PROPERTY = "saml.idp.replay.type";

  /** Property value for an in-memory replay cache. */
  private static final String TYPE_MEMORY = "memory";

  /** Property value for a Redis replay cache. */
  private static final String TYPE_REDIS = "redis";

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
   * Creates the {@link ReplayCache} bean according to the {@code saml.idp.replay.type} property, see
   * {@link MessageReplayCheckerAutoConfiguration}.
   *
   * @param redisReplayCacheSupplier supplier of a Redis based cache, present only if Redis is on the classpath
   * @return a {@link ReplayCache}
   * @throws IllegalArgumentException if the property has an unknown value, or if a Redis cache is requested but no
   *           {@link StringRedisTemplate} bean is available
   */
  @ConditionalOnMissingBean
  @Bean
  ReplayCache replayCache(final ObjectProvider<RedisReplayCacheSupplier> redisReplayCacheSupplier) {

    final String type = this.properties.getReplay().getType();
    final ReplayCache redisCache = Optional.ofNullable(redisReplayCacheSupplier.getIfAvailable())
        .map(RedisReplayCacheSupplier::get)
        .orElse(null);

    if (!StringUtils.hasText(type)) {
      if (redisCache != null) {
        log.info("{} is not set and Redis is available - using {}", TYPE_PROPERTY,
            redisCache.getClass().getSimpleName());
        return redisCache;
      }
      log.info("{} is not set and Redis is not available - using {}", TYPE_PROPERTY,
          InMemoryReplayCache.class.getSimpleName());
      return new InMemoryReplayCache();
    }

    if (TYPE_MEMORY.equalsIgnoreCase(type)) {
      log.info("{} is '{}' - using {}", TYPE_PROPERTY, type, InMemoryReplayCache.class.getSimpleName());
      return new InMemoryReplayCache();
    }

    if (TYPE_REDIS.equalsIgnoreCase(type)) {
      if (redisCache == null) {
        throw new IllegalArgumentException(
            "%s is '%s', but Redis is not available - a StringRedisTemplate bean is required"
                .formatted(TYPE_PROPERTY, type));
      }
      log.info("{} is '{}' - using {}", TYPE_PROPERTY, type, redisCache.getClass().getSimpleName());
      return redisCache;
    }

    throw new IllegalArgumentException("Invalid value for %s: '%s' - expected '%s' or '%s'"
        .formatted(TYPE_PROPERTY, type, TYPE_MEMORY, TYPE_REDIS));
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
   * Supplier of a Redis based {@link ReplayCache}. A bean of this type exists only if Spring Data Redis is on the
   * classpath.
   */
  interface RedisReplayCacheSupplier {

    /**
     * Gets a Redis based {@link ReplayCache}.
     *
     * @return a {@link ReplayCache}, or null if no {@link StringRedisTemplate} bean is available
     */
    ReplayCache get();
  }

  /**
   * For configuration of a {@link RedisReplayCache} bean.
   */
  @ConditionalOnClass(StringRedisTemplate.class)
  @Configuration
  public static class RedisMessageReplayCheckerConfiguration {

    /**
     * Supplies a {@link RedisReplayCache} if a {@link StringRedisTemplate} bean is available. The template is looked up
     * when the cache is asked for, so that the outcome does not depend on the order in which autoconfigurations are
     * applied.
     *
     * @param redisTemplate provider of the Redis template
     * @return a {@link RedisReplayCacheSupplier}
     */
    @Bean
    RedisReplayCacheSupplier redisReplayCacheSupplier(final ObjectProvider<StringRedisTemplate> redisTemplate) {
      return () -> Optional.ofNullable(redisTemplate.getIfAvailable())
          .map(RedisReplayCache::new)
          .orElse(null);
    }

  }

}
