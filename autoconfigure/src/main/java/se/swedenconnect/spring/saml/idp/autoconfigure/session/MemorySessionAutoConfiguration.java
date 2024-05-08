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
package se.swedenconnect.spring.saml.idp.autoconfigure.session;

import java.io.Serial;
import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.session.SessionAutoConfiguration;
import org.springframework.boot.autoconfigure.session.SessionProperties;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.session.MapSessionRepository;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.session.config.annotation.web.http.EnableSpringHttpSession;
import se.swedenconnect.spring.saml.idp.Saml2IdentityProviderVersion;

/**
 * Configuration class for setting up Spring Session to use an in-memory map for storing sessions.
 *
 * @author Martin Lindström
 */
@ConditionalOnProperty(value = "saml.idp.session.module", havingValue = "memory", matchIfMissing = true)
@ConditionalOnClass(Session.class)
@ConditionalOnMissingBean(SessionRepository.class)
@ConditionalOnWebApplication
@AutoConfiguration(before = SessionAutoConfiguration.class, after = RedisSessionAutoConfiguration.class)
@EnableConfigurationProperties({ ServerProperties.class, SessionProperties.class })
@EnableSpringHttpSession
@EnableScheduling
public class MemorySessionAutoConfiguration {

  /** Server properties. */
  private final ServerProperties serverProperties;

  /** Session properties. */
  private final SessionProperties sessionProperties;

  /**
   * Constructor.
   *
   * @param serverProperties the server properties
   * @param sessionProperties the session properties
   */
  public MemorySessionAutoConfiguration(
      final ServerProperties serverProperties, final SessionProperties sessionProperties) {
    this.serverProperties = serverProperties;
    this.sessionProperties = sessionProperties;
  }

  /**
   * Creates an in-memory session repository.
   *
   * @param sessionMap the map to hold the session objects
   * @return a {@link MapSessionRepository} bean
   */
  @Bean
  MapSessionRepository sessionRepository(final PurgeableMap sessionMap) {

    final Duration timeout = this.sessionProperties.determineTimeout(
        () -> this.serverProperties.getServlet().getSession().getTimeout());

    final MapSessionRepository sessionRepository = new MapSessionRepository(sessionMap);
    sessionRepository.setDefaultMaxInactiveInterval(timeout);

    return sessionRepository;
  }

  /**
   * Creates the map holding the sessions.
   *
   * @return a {@code PurgeableMap}
   */
  @Bean
  PurgeableMap sessionMap() {
    return new PurgeableMap();
  }

  /**
   * A {@link ConcurrentHashMap} that has support for purging expired sessions.
   */
  private static class PurgeableMap extends ConcurrentHashMap<String, Session> {

    @Serial
    private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

    /**
     * Purges expired sessions.
     */
    @Scheduled(fixedDelay = 600000L)
    public void purgeExpired() {
      this.entrySet().removeIf(e -> e.getValue().isExpired());
    }

  }

}
