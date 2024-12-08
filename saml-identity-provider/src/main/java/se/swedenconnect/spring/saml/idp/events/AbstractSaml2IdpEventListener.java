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
package se.swedenconnect.spring.saml.idp.events;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;
import se.swedenconnect.security.credential.spring.monitoring.events.AbstractCredentialMonitoringEvent;
import se.swedenconnect.security.credential.spring.monitoring.events.FailedCredentialReloadEvent;
import se.swedenconnect.security.credential.spring.monitoring.events.FailedCredentialTestEvent;
import se.swedenconnect.security.credential.spring.monitoring.events.SuccessfulCredentialReloadEvent;

/**
 * Abstract base class for an {@link ApplicationListener} for SAML2 events.
 *
 * @author Martin Lindström
 */
@Slf4j
public abstract class AbstractSaml2IdpEventListener implements ApplicationListener<ApplicationEvent> {

  /**
   * Routes the received event to the correct on-method.
   */
  @Override
  public void onApplicationEvent(@Nullable final ApplicationEvent event) {
    if (event == null) {
      return;
    }
    if (event instanceof AbstractSaml2IdpEvent || event instanceof AbstractCredentialMonitoringEvent) {
      log.debug("Received {} event", event.getClass().getSimpleName());
    }

    if (event instanceof final Saml2AuthnRequestReceivedEvent e) {
      this.onAuthnRequestReceivedEvent(e);
    }
    else if (event instanceof final Saml2SuccessResponseEvent e) {
      this.onSuccessResponseEvent(e);
    }
    else if (event instanceof final Saml2ErrorResponseEvent e) {
      this.onErrorResponseEvent(e);
    }
    else if (event instanceof final Saml2PreUserAuthenticationEvent e) {
      this.onPreUserAuthenticationEvent(e);
    }
    else if (event instanceof final Saml2PostUserAuthenticationEvent e) {
      this.onPostUserAuthenticationEvent(e);
    }
    else if (event instanceof final Saml2UnrecoverableErrorEvent e) {
      this.onUnrecoverableErrorEvent(e);
    }
    else if (event instanceof final FailedCredentialTestEvent e) {
      this.onFailedCredentialTestEvent(e);
    }
    else if (event instanceof final SuccessfulCredentialReloadEvent e) {
      this.onSuccessfulCredentialReloadEvent(e);
    }
    else if (event instanceof final FailedCredentialReloadEvent e) {
      this.onFailedCredentialReloadEvent(e);
    }
  }

  /**
   * Handles a {@link Saml2AuthnRequestReceivedEvent} event. The default implementation does nothing.
   *
   * @param event the event
   */
  protected void onAuthnRequestReceivedEvent(@Nonnull final Saml2AuthnRequestReceivedEvent event) {
  }

  /**
   * Handles a {@link Saml2SuccessResponseEvent} event. The default implementation does nothing.
   *
   * @param event the event
   */
  protected void onSuccessResponseEvent(@Nonnull final Saml2SuccessResponseEvent event) {
  }

  /**
   * Handles a {@link Saml2ErrorResponseEvent} event. The default implementation does nothing.
   *
   * @param event the event
   */
  protected void onErrorResponseEvent(@Nonnull final Saml2ErrorResponseEvent event) {
  }

  /**
   * Handles a {@link Saml2PreUserAuthenticationEvent} event. The default implementation does nothing.
   *
   * @param event the event
   */
  protected void onPreUserAuthenticationEvent(@Nonnull final Saml2PreUserAuthenticationEvent event) {
  }

  /**
   * Handles a {@link Saml2PostUserAuthenticationEvent} event. The default implementation does nothing.
   *
   * @param event the event
   */
  protected void onPostUserAuthenticationEvent(@Nonnull final Saml2PostUserAuthenticationEvent event) {
  }

  /**
   * Handles a {@link Saml2UnrecoverableErrorEvent} event. The default implementation does nothing.
   *
   * @param event the event
   */
  protected void onUnrecoverableErrorEvent(@Nonnull final Saml2UnrecoverableErrorEvent event) {
  }

  /**
   * Handles a {@link FailedCredentialTestEvent} event. The default implementation does nothing.
   *
   * @param event the event
   */
  protected void onFailedCredentialTestEvent(@Nonnull final FailedCredentialTestEvent event) {
  }

  /**
   * Handles a {@link SuccessfulCredentialReloadEvent} event. The default implementation does nothing.
   *
   * @param event the event
   */
  protected void onSuccessfulCredentialReloadEvent(@Nonnull final SuccessfulCredentialReloadEvent event) {
  }

  /**
   * Handles a {@link FailedCredentialReloadEvent} event. The default implementation does nothing.
   *
   * @param event the event
   */
  protected void onFailedCredentialReloadEvent(@Nonnull final FailedCredentialReloadEvent event) {
  }

}
