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
package se.swedenconnect.spring.saml.idp.authnrequest.validation.replay;

import java.time.Instant;
import java.util.Objects;

import org.opensaml.storage.ReplayCache;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ZSetOperations;

import lombok.extern.slf4j.Slf4j;

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
  public boolean check(final String context, final String key, final Instant expires) {

    // Remove expired entries ...
    //
    final Long noRemoved = this.redisSet.removeRangeByScore(context, 0, Instant.now().getEpochSecond());
    log.trace("Removed {} expired entries in Redis replay cache", noRemoved);

    // If the key is present, we return false, otherwise we add the key to the set and return true.
    //
    if (this.redisSet.rank(context, key) != null) {
      log.debug("Key '{}' was present in Redis replay cache ({}), returning false", key, context);
      return false;
    }
    else {
      this.redisSet.add(context, key, expires.getEpochSecond());
      log.trace("Key '{}' was not present in Redis replay cache ({}), adding it and returning true", key, context);
      return true;
    }

  }

}
