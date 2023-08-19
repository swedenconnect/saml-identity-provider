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
package se.swedenconnect.spring.saml.idp.events;

import org.springframework.context.ApplicationListener;

import lombok.extern.slf4j.Slf4j;

/**
 * Abstract base class for an {@link ApplicationListener} for SAML2 events.
 * 
 * @author Martin Lindström
 */
@Slf4j
public class AbstractSaml2IdpEventListener implements ApplicationListener<AbstractSaml2IdpEvent> {
  
  /**
   * Routes the received event to the correct on-method.
   */
  @Override
  public void onApplicationEvent(final AbstractSaml2IdpEvent event) {
    log.debug("Received {} event", event.getClass().getSimpleName());
    
    if (event instanceof Saml2AuthnRequestReceivedEvent e) {
      this.onAuthnRequestReceivedEvent(e);
    }
    else if (event instanceof Saml2SuccessResponseEvent e) {
      this.onSuccessResponseEvent(e);
    }
    else if (event instanceof Saml2ErrorResponseEvent e) {
      this.onErrorResponseEvent(e);
    }
    else if (event instanceof Saml2PreUserAuthenticationEvent e) {
      this.onPreUserAuthenticationEvent(e);
    }
    else if (event instanceof Saml2PostUserAuthenticationEvent e) {
      this.onPostUserAuthenticationEvent(e);
    }
    else if (event instanceof Saml2UnrecoverableErrorEvent e) {
      this.onUnrecoverableErrorEvent(e);
    }
  }

  /**
   * Handles a {@link Saml2AuthnRequestReceivedEvent} event. The default implementation does nothing.
   * 
   * @param event the event
   */
  protected void onAuthnRequestReceivedEvent(final Saml2AuthnRequestReceivedEvent event) {
  }

  /**
   * Handles a {@link Saml2SuccessResponseEvent} event. The default implementation does nothing.
   * 
   * @param event the event
   */  
  protected void onSuccessResponseEvent(final Saml2SuccessResponseEvent event) {
  }

  /**
   * Handles a {@link Saml2ErrorResponseEvent} event. The default implementation does nothing.
   * 
   * @param event the event
   */  
  protected void onErrorResponseEvent(final Saml2ErrorResponseEvent event) {
  }

  /**
   * Handles a {@link Saml2PreUserAuthenticationEvent} event. The default implementation does nothing.
   * 
   * @param event the event
   */  
  protected void onPreUserAuthenticationEvent(final Saml2PreUserAuthenticationEvent event) {
  }

  /**
   * Handles a {@link Saml2PostUserAuthenticationEvent} event. The default implementation does nothing.
   * 
   * @param event the event
   */  
  protected void onPostUserAuthenticationEvent(final Saml2PostUserAuthenticationEvent event) {
  }
  
  /**
   * Handles a {@link Saml2UnrecoverableErrorEvent} event. The default implementation does nothing.
   * 
   * @param event the event
   */
  protected void onUnrecoverableErrorEvent(final Saml2UnrecoverableErrorEvent event) {    
  }

}
