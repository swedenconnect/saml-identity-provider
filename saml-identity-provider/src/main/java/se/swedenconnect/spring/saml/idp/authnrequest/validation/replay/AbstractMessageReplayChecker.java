/*
 * Copyright 2023 Sweden Connect
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

import java.time.Duration;

import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.saml2.core.RequestAbstractType;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.opensaml.saml2.response.replay.MessageReplayChecker;
import se.swedenconnect.opensaml.saml2.response.replay.MessageReplayException;

/**
 * Abstract base class for {@link MessageReplayChecker}.
 *
 * @author Martin Lindström
 */
@Slf4j
public abstract class AbstractMessageReplayChecker implements MessageReplayChecker {

  /** The default replay cache expiration time - 5 minutes. */
  public static final Duration DEFAULT_REPLAY_CACHE_EXPIRATION = Duration.ofMinutes(5);

  /** Time to keep elements in the replay cache - default is {@link #DEFAULT_REPLAY_CACHE_EXPIRATION}. */
  protected Duration replayCacheExpiration = DEFAULT_REPLAY_CACHE_EXPIRATION;

  /** {@inheritDoc} */
  @Override
  public void checkReplay(final String id) throws MessageReplayException {
    if (this.existsInCache(id)) {
      final String msg = "Replay check of ID '%s' failed".formatted(id);
      log.info(msg);
      throw new MessageReplayException(msg);
    }
    else {
      this.addToCache(id);
      log.debug("Message replay check of ID '{}' succeeded", id);
    }
  }

  /**
   * Predicate that returns {@code true} if the {@code id} object exists in the cache and has not expired.
   *
   * @param id the ID
   * @return {@code true} if the object exists in the cache and has not expired, and {@code false} otherwise
   */
  protected abstract boolean existsInCache(final String id);

  /**
   * Adds the {@code id} object to the cache where it will be stored until it expires.
   *
   * @param id the ID
   */
  protected abstract void addToCache(final String id);

  /** {@inheritDoc} */
  @Override
  public void checkReplay(final SAMLObject object) throws MessageReplayException, IllegalArgumentException {
    String id = null;
    if (object instanceof RequestAbstractType r) {
      id = r.getID();
    }
    if (id == null) {
      throw new IllegalArgumentException("Unsupported object type");
    }
    this.checkReplay(id);
  }

  /**
   * Assigns the time each stored ID should be kept in the cache. The default is
   * {@link #DEFAULT_REPLAY_CACHE_EXPIRATION}.
   *
   * @param replayCacheExpiration duration
   */
  public void setReplayCacheExpiration(final Duration replayCacheExpiration) {
    if (replayCacheExpiration != null) {
      this.replayCacheExpiration = replayCacheExpiration;
    }
  }
}
