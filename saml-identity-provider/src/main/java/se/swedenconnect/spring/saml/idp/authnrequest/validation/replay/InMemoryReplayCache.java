/*
 * Copyright 2024 Sweden Connect
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
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.opensaml.storage.ReplayCache;

import lombok.extern.slf4j.Slf4j;

/**
 * An in-memory implementation of the {@link ReplayCache} interface.
 *
 * @author Martin Lindström
 */
@Slf4j
public class InMemoryReplayCache implements ReplayCache {

  /** The cache. */
  private final ConcurrentMap<String, Long> cache = new ConcurrentHashMap<>();

  /**
   * Constructor.
   */
  public InMemoryReplayCache() {
    log.warn("{} is used, consider using a distributed cache for production", this.getClass().getSimpleName());
  }

  /** {@inheritDoc} */
  @Override
  public boolean check(final String context, final String key, final Instant expires) {

    // Remove expired entries ...
    //
    final long now = Instant.now().getEpochSecond();
    this.cache.entrySet().removeIf(e -> e.getValue() < now);

    if (this.cache.containsKey(key)) {
      log.debug("Key '{}' was present in in-memory replay cache, returning false", key);
      return false;
    }
    else {
      this.cache.put(key, expires.getEpochSecond());
      log.trace("Key '{}' was not present in in-memory replay cache, adding it and returning true", key);
      return true;
    }
  }

}
