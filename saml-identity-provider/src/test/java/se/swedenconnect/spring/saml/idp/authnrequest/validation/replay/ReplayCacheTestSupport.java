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
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Assertions;
import org.opensaml.storage.ReplayCache;

/**
 * Support for the replay cache test cases.
 *
 * @author Martin Lindström
 */
class ReplayCacheTestSupport {

  /** The context to use when testing. */
  static final String CONTEXT = "test-context";

  /** The number of threads calling the cache at the same time. */
  private static final int THREADS = 32;

  /** The number of keys to test with. */
  private static final int KEYS = 50;

  /**
   * Gets an expiration instant well into the future.
   *
   * @return an expiration instant
   */
  static Instant expires() {
    return Instant.now().plusSeconds(300);
  }

  /**
   * Asserts that exactly one of a number of concurrent calls for the same key gets {@code true}, and that this holds
   * for every one of a number of keys.
   *
   * @param cache the cache to test
   * @throws Exception for test errors
   */
  static void assertOneAcceptedPerKey(final ReplayCache cache) throws Exception {

    final ExecutorService executor = Executors.newFixedThreadPool(THREADS);
    try {
      for (int k = 0; k < KEYS; k++) {
        final String key = "key-" + k;
        final CountDownLatch startGate = new CountDownLatch(1);
        final List<Future<Boolean>> results = new ArrayList<>();

        for (int t = 0; t < THREADS; t++) {
          results.add(executor.submit(() -> {
            startGate.await();
            return cache.check(CONTEXT, key, expires());
          }));
        }
        startGate.countDown();

        int accepted = 0;
        for (final Future<Boolean> result : results) {
          if (result.get(30, TimeUnit.SECONDS)) {
            accepted++;
          }
        }
        Assertions.assertEquals(1, accepted,
            "Expected exactly one of %d concurrent calls for key '%s' to get true".formatted(THREADS, key));
      }
    }
    finally {
      executor.shutdownNow();
    }
  }

}
