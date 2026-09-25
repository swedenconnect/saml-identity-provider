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

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.opensaml.storage.ReplayCache;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ZSetOperations;

/**
 * Test cases for RedisReplayCache.
 * <p>
 * No Redis server is available in this project, so the Redis sorted set is replaced by a map based stand-in that
 * implements {@code addIfAbsent} the way the Redis {@code ZADD NX} command does, i.e. as one atomic operation. This
 * makes it possible to assert that the cache relies on that single operation, and that it behaves correctly when
 * several threads call it at the same time.
 * </p>
 *
 * @author Martin Lindström
 */
public class RedisReplayCacheTest {

  /** The sorted set stand-in, a map of context to a map of key and expiration time. */
  private final ConcurrentMap<String, ConcurrentMap<String, Double>> sortedSets = new ConcurrentHashMap<>();

  /** Mock of the Redis operations. */
  private ZSetOperations<String, String> redisSet;

  /** The cache under test. */
  private ReplayCache cache;

  @SuppressWarnings("unchecked")
  @BeforeEach
  public void setup() {
    this.redisSet = Mockito.mock(ZSetOperations.class);

    Mockito.when(this.redisSet.addIfAbsent(ArgumentMatchers.anyString(), ArgumentMatchers.anyString(),
        ArgumentMatchers.anyDouble()))
        .thenAnswer(invocation -> this.entries(invocation.getArgument(0))
            .putIfAbsent(invocation.getArgument(1), invocation.getArgument(2)) == null);

    Mockito.when(this.redisSet.removeRangeByScore(ArgumentMatchers.anyString(), ArgumentMatchers.anyDouble(),
        ArgumentMatchers.anyDouble()))
        .thenAnswer(invocation -> {
          final double min = invocation.getArgument(1);
          final double max = invocation.getArgument(2);
          final Map<String, Double> entries = this.entries(invocation.getArgument(0));
          final int before = entries.size();
          entries.values().removeIf(score -> score >= min && score <= max);
          return (long) (before - entries.size());
        });

    final StringRedisTemplate redisTemplate = Mockito.mock(StringRedisTemplate.class);
    Mockito.when(redisTemplate.opsForZSet()).thenReturn(this.redisSet);

    this.cache = new RedisReplayCache(redisTemplate);
  }

  @Test
  public void testCheck() {
    Assertions.assertTrue(this.cache.check(ReplayCacheTestSupport.CONTEXT, "key", ReplayCacheTestSupport.expires()));
    Assertions.assertFalse(this.cache.check(ReplayCacheTestSupport.CONTEXT, "key", ReplayCacheTestSupport.expires()));
    Assertions.assertTrue(
        this.cache.check(ReplayCacheTestSupport.CONTEXT, "other-key", ReplayCacheTestSupport.expires()));
  }

  @Test
  public void testSeparateContexts() {
    Assertions.assertTrue(this.cache.check(ReplayCacheTestSupport.CONTEXT, "key", ReplayCacheTestSupport.expires()));
    Assertions.assertTrue(this.cache.check("other-context", "key", ReplayCacheTestSupport.expires()));
  }

  @Test
  public void testExpiredEntryIsAcceptedAgain() {
    final Instant expired = Instant.now().minusSeconds(10);
    Assertions.assertTrue(this.cache.check(ReplayCacheTestSupport.CONTEXT, "key", expired));
    Assertions.assertTrue(this.cache.check(ReplayCacheTestSupport.CONTEXT, "key", ReplayCacheTestSupport.expires()));
    Assertions.assertFalse(this.cache.check(ReplayCacheTestSupport.CONTEXT, "key", ReplayCacheTestSupport.expires()));
  }

  @Test
  public void testConcurrentCheck() throws Exception {
    ReplayCacheTestSupport.assertOneAcceptedPerKey(this.cache);
  }

  /**
   * Asserts that the key is added with one operation, and that no separate check for presence is made.
   */
  @Test
  public void testOneOperationIsUsed() {
    this.cache.check(ReplayCacheTestSupport.CONTEXT, "key", ReplayCacheTestSupport.expires());

    Mockito.verify(this.redisSet).addIfAbsent(ArgumentMatchers.eq(ReplayCacheTestSupport.CONTEXT),
        ArgumentMatchers.eq("key"), ArgumentMatchers.anyDouble());
    Mockito.verify(this.redisSet, Mockito.never()).rank(ArgumentMatchers.anyString(), ArgumentMatchers.any());
    Mockito.verify(this.redisSet, Mockito.never()).add(ArgumentMatchers.anyString(), ArgumentMatchers.anyString(),
        ArgumentMatchers.anyDouble());
  }

  /**
   * If Redis does not tell whether the key was added, the key is treated as already present.
   */
  @Test
  public void testNoResultFromRedis() {
    Mockito.when(this.redisSet.addIfAbsent(ArgumentMatchers.anyString(), ArgumentMatchers.anyString(),
        ArgumentMatchers.anyDouble())).thenReturn(null);

    Assertions.assertFalse(this.cache.check(ReplayCacheTestSupport.CONTEXT, "key", ReplayCacheTestSupport.expires()));
  }

  /**
   * Gets the entries for the given context.
   *
   * @param context the context
   * @return the entries for the context
   */
  private ConcurrentMap<String, Double> entries(final String context) {
    return this.sortedSets.computeIfAbsent(context, c -> new ConcurrentHashMap<>());
  }

}
