/*
 * Copyright 2023-2025 Sweden Connect
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

import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Response;
import org.springframework.context.ApplicationEventPublisher;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthentication;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthenticationInputToken;
import se.swedenconnect.spring.saml.idp.authentication.provider.UserAuthenticationProvider;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpException;

import java.util.Objects;

/**
 * A publisher for SAML IdP events.
 *
 * @author Martin Lindström
 */
public class Saml2IdpEventPublisher {

  /** The system's event publisher. */
  private final ApplicationEventPublisher publisher;

  /**
   * Constructor.
   *
   * @param publisher the system's event publisher
   */
  public Saml2IdpEventPublisher(final ApplicationEventPublisher publisher) {
    this.publisher = Objects.requireNonNull(publisher, "publisher must not be null");
  }

  /**
   * Publishes a {@link Saml2AuthnRequestReceivedEvent} indicating that a SAML {@code AuthnRequest} was received.
   *
   * @param token the {@link Saml2AuthnRequestAuthenticationToken}
   */
  public void publishAuthnRequestReceived(final Saml2AuthnRequestAuthenticationToken token) {
    this.publisher.publishEvent(new Saml2AuthnRequestReceivedEvent(token));
  }

  /**
   * Publishes a {@link Saml2SuccessResponseEvent} indicating that a successful SAML response is about to be sent.
   *
   * @param response the SAML response
   * @param assertion the SAML Assertion (before being encrypted)
   * @param spEntityId the entityID of the SP that we are sending the response to
   */
  public void publishSamlSuccessResponse(final Response response, final Assertion assertion, final String spEntityId) {
    this.publisher.publishEvent(new Saml2SuccessResponseEvent(response, assertion, spEntityId));
  }

  /**
   * Publishes a {@link Saml2ErrorResponseEvent} indicating that a SAML error response is about to be sent.
   *
   * @param response the SAML {@link Response}
   * @param entityId the SAML entityID of the recipient
   */
  public void publishSamlErrorResponse(final Response response, final String entityId) {
    this.publisher.publishEvent(new Saml2ErrorResponseEvent(response, entityId));
  }

  /**
   * Publishes a {@link Saml2PreUserAuthenticationEvent}. This is fired before the user is authenticated but after all
   * the input SAML processing has been performed.
   *
   * @param token a {@link Saml2UserAuthenticationInputToken} token
   */
  public void publishBeforeUserAuthenticated(final Saml2UserAuthenticationInputToken token) {
    this.publisher.publishEvent(new Saml2PreUserAuthenticationEvent(token));
  }

  /**
   * Publishes a {@link Saml2PostUserAuthenticationEvent} indicating that an {@link UserAuthenticationProvider} has
   * authenticated the user.
   *
   * @param authn the {@link Saml2UserAuthentication}
   */
  public void publishUserAuthenticated(final Saml2UserAuthentication authn) {
    this.publisher.publishEvent(new Saml2PostUserAuthenticationEvent(authn));
  }

  /**
   * Publishes a {@link Saml2UnrecoverableErrorEvent} indicating that an {@link UnrecoverableSaml2IdpException} has been
   * thrown.
   *
   * @param error the {@link UnrecoverableSaml2IdpException} error
   */
  public void publishUnrecoverableSamlError(final UnrecoverableSaml2IdpException error) {
    this.publisher.publishEvent(new Saml2UnrecoverableErrorEvent(error));
  }
}
