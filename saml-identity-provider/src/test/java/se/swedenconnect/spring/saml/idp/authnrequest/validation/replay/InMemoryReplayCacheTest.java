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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.opensaml.storage.ReplayCache;

/**
 * Test cases for InMemoryReplayCache.
 *
 * @author Martin Lindström
 */
public class InMemoryReplayCacheTest {

  @Test
  public void testCheck() {
    final ReplayCache cache = new InMemoryReplayCache();

    Assertions.assertTrue(cache.check(ReplayCacheTestSupport.CONTEXT, "key", ReplayCacheTestSupport.expires()));
    Assertions.assertFalse(cache.check(ReplayCacheTestSupport.CONTEXT, "key", ReplayCacheTestSupport.expires()));
    Assertions.assertTrue(cache.check(ReplayCacheTestSupport.CONTEXT, "other-key", ReplayCacheTestSupport.expires()));
  }

  @Test
  public void testExpiredEntryIsAcceptedAgain() {
    final ReplayCache cache = new InMemoryReplayCache();

    final Instant expired = Instant.now().minusSeconds(10);
    Assertions.assertTrue(cache.check(ReplayCacheTestSupport.CONTEXT, "key", expired));
    Assertions.assertTrue(cache.check(ReplayCacheTestSupport.CONTEXT, "key", ReplayCacheTestSupport.expires()));
    Assertions.assertFalse(cache.check(ReplayCacheTestSupport.CONTEXT, "key", ReplayCacheTestSupport.expires()));
  }

  @Test
  public void testConcurrentCheck() throws Exception {
    final ReplayCache cache = new InMemoryReplayCache();

    ReplayCacheTestSupport.assertOneAcceptedPerKey(cache);
  }

}
