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
package se.swedenconnect.spring.saml.idp.authnrequest.validation.replay;

import jakarta.annotation.Nonnull;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.storage.ReplayCache;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ZSetOperations;

import java.time.Instant;
import java.util.Objects;

/**
 * A generic Redis {@link ReplayCache} implementation.
 *
 * @author Martin Lindström
 */
@Slf4j
public class RedisReplayCache implements ReplayCache {

  /** The Redis set. */
  private final ZSetOperations<String, String> redisSet;

  /**
   * Constructor.
   *
   * @param redisTemplate the Redis template
   */
  public RedisReplayCache(final StringRedisTemplate redisTemplate) {
    this.redisSet = Objects.requireNonNull(redisTemplate, "redisTemplate must not be null").opsForZSet();
  }

  /** {@inheritDoc} */
  @Override
  public boolean check(@Nonnull final String context, @Nonnull final String key, @Nonnull final Instant expires) {

    // Remove expired entries ...
    //
    final Long noRemoved = this.redisSet.removeRangeByScore(context, 0, Instant.now().getEpochSecond());
    log.trace("Removed {} expired entries in Redis replay cache", noRemoved);

    // Add the key to the set if it is not already present. This is one operation on the Redis server (ZADD NX),
    // meaning that only one of any number of concurrent calls for the same key gets true.
    //
    final Boolean added = this.redisSet.addIfAbsent(context, key, expires.getEpochSecond());
    if (added == null) {
      log.warn("Redis did not report whether key '{}' was added to the replay cache ({}), returning false",
          key, context);
      return false;
    }
    if (added) {
      log.trace("Key '{}' was not present in Redis replay cache ({}), adding it and returning true", key, context);
      return true;
    }
    else {
      log.debug("Key '{}' was present in Redis replay cache ({}), returning false", key, context);
      return false;
    }
  }

}
