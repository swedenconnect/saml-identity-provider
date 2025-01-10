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
package se.swedenconnect.spring.saml.idp.audit;

import jakarta.annotation.Nonnull;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.Response;
import org.springframework.boot.actuate.audit.listener.AuditApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import se.swedenconnect.security.credential.spring.monitoring.events.FailedCredentialReloadEvent;
import se.swedenconnect.security.credential.spring.monitoring.events.FailedCredentialTestEvent;
import se.swedenconnect.security.credential.spring.monitoring.events.SuccessfulCredentialReloadEvent;
import se.swedenconnect.spring.saml.idp.audit.data.Saml2AssertionAuditData;
import se.swedenconnect.spring.saml.idp.audit.data.Saml2AuthnRequestAuditData;
import se.swedenconnect.spring.saml.idp.audit.data.Saml2ResponseAuditData;
import se.swedenconnect.spring.saml.idp.audit.data.Saml2UnrecoverableErrorAuditData;
import se.swedenconnect.spring.saml.idp.audit.data.Saml2UserAuthenticationInfoAuditData;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthentication;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthenticationInputToken;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;
import se.swedenconnect.spring.saml.idp.events.AbstractSaml2IdpEventListener;
import se.swedenconnect.spring.saml.idp.events.Saml2AuthnRequestReceivedEvent;
import se.swedenconnect.spring.saml.idp.events.Saml2ErrorResponseEvent;
import se.swedenconnect.spring.saml.idp.events.Saml2PostUserAuthenticationEvent;
import se.swedenconnect.spring.saml.idp.events.Saml2PreUserAuthenticationEvent;
import se.swedenconnect.spring.saml.idp.events.Saml2SuccessResponseEvent;
import se.swedenconnect.spring.saml.idp.events.Saml2UnrecoverableErrorEvent;

import java.util.Objects;
import java.util.Optional;

/**
 * An event listener that handles the events publishes by the SAML IdP, translates them to audit events and publishes
 * them.
 *
 * @author Martin Lindström
 */
@Slf4j
public class Saml2IdpAuditListener extends AbstractSaml2IdpEventListener {

  /** The system event publisher. */
  private final ApplicationEventPublisher publisher;

  /**
   * Constructor.
   *
   * @param publisher the system event publisher
   */
  public Saml2IdpAuditListener(@Nonnull final ApplicationEventPublisher publisher) {
    this.publisher = Objects.requireNonNull(publisher, "publisher must not be null");
  }

  /**
   * An {@link AuthnRequest} has been received. Publishes an audit event containing {@link Saml2AuthnRequestAuditData}.
   */
  @Override
  protected void onAuthnRequestReceivedEvent(@Nonnull final Saml2AuthnRequestReceivedEvent event) {

    final Saml2AuditEvent auditEvent =
        new Saml2AuditEvent(Saml2AuditEvents.SAML2_AUDIT_REQUEST_RECEIVED, event.getTimestamp(),
            event.getSpEntityId(), Optional.ofNullable(event.getAuthnRequest()).map(AuthnRequest::getID).orElse(null),
            Saml2AuthnRequestAuditData.of(event.getAuthnRequest(), event.getAuthnRequestToken().getRelayState()));

    log.info("Publishing audit event: {}", auditEvent.getLogString());

    this.publish(auditEvent);
  }

  /**
   * A successful SAML response is about to be sent. Publishes an audit event containing a
   * {@link Saml2ResponseAuditData} and a {@link Saml2AssertionAuditData}.
   */
  @Override
  protected void onSuccessResponseEvent(@Nonnull final Saml2SuccessResponseEvent event) {

    final Saml2AuditEvent auditEvent =
        new Saml2AuditEvent(Saml2AuditEvents.SAML2_AUDIT_SUCCESSFUL_RESPONSE, event.getTimestamp(),
            event.getSpEntityId(), Optional.ofNullable(event.getResponse()).map(Response::getInResponseTo).orElse(null),
            Saml2ResponseAuditData.of(event.getResponse()), Saml2AssertionAuditData.of(event.getAssertion(),
            Optional.ofNullable(event.getResponse())
                .map(Response::getEncryptedAssertions)
                .filter(l -> !l.isEmpty())
                .isPresent()));

    log.info("Publishing audit event: {}", auditEvent.getLogString());

    this.publish(auditEvent);
  }

  /**
   * An error SAML status is about to be sent. Publishes an audit event containing {@link Saml2ResponseAuditData}.
   */
  @Override
  protected void onErrorResponseEvent(@Nonnull final Saml2ErrorResponseEvent event) {

    final Saml2AuditEvent auditEvent =
        new Saml2AuditEvent(Saml2AuditEvents.SAML2_AUDIT_ERROR_RESPONSE, event.getTimestamp(),
            event.getSpEntityId(), Optional.ofNullable(event.getResponse()).map(Response::getInResponseTo).orElse(null),
            Saml2ResponseAuditData.of(event.getResponse()));

    log.info("Publishing audit event: {}", auditEvent.getLogString());

    this.publish(auditEvent);
  }

  /**
   * An event that is fired after we have received and successfully processed a SAML request, but before the user is
   * authenticated.
   */
  @Override
  protected void onPreUserAuthenticationEvent(@Nonnull final Saml2PreUserAuthenticationEvent event) {

    final AuthnRequest authnRequest = Optional.ofNullable(event.getUserAuthenticationInput())
        .map(Saml2UserAuthenticationInputToken::getAuthnRequestToken)
        .map(Saml2AuthnRequestAuthenticationToken::getAuthnRequest)
        .orElse(null);

    final Saml2AuditEvent auditEvent =
        new Saml2AuditEvent(Saml2AuditEvents.SAML2_AUDIT_BEFORE_USER_AUTHN, event.getTimestamp(),
            Optional.ofNullable(authnRequest).map(AuthnRequest::getIssuer).map(Issuer::getValue).orElse(null),
            Optional.ofNullable(authnRequest).map(AuthnRequest::getID).orElse(null));

    log.info("Publishing audit event: {}", auditEvent.getLogString());

    this.publish(auditEvent);
  }

  /**
   * The user has been successfully authenticated, but the SAML assertion has not yet been created. Publishes an audit
   * event containing {@link Saml2UserAuthenticationInfoAuditData}.
   */
  @Override
  protected void onPostUserAuthenticationEvent(@Nonnull final Saml2PostUserAuthenticationEvent event) {

    final Saml2UserAuthentication userAuthn = event.getUserAuthentication();

    final Saml2AuditEvent auditEvent =
        new Saml2AuditEvent(Saml2AuditEvents.SAML2_AUDIT_AFTER_USER_AUTHN, event.getTimestamp(),
            Optional.ofNullable(userAuthn.getAuthnRequestToken())
                .map(Saml2AuthnRequestAuthenticationToken::getEntityId)
                .orElse(null),
            Optional.ofNullable(userAuthn.getAuthnRequestToken())
                .map(Saml2AuthnRequestAuthenticationToken::getAuthnRequest)
                .map(AuthnRequest::getID)
                .orElse(null),
            Saml2UserAuthenticationInfoAuditData.of(userAuthn,
                Optional.ofNullable(userAuthn.getAuthnRequestToken())
                    .map(Saml2AuthnRequestAuthenticationToken::isSignatureServicePeer)
                    .orElse(false)));

    log.info("Publishing audit event: {}", auditEvent.getLogString());

    this.publish(auditEvent);
  }

  /**
   * An unrecoverable error has occurred. Publishes an audit event containing {@link Saml2UnrecoverableErrorAuditData}.
   */
  @Override
  protected void onUnrecoverableErrorEvent(@Nonnull final Saml2UnrecoverableErrorEvent event) {
    final Saml2AuditEvent auditEvent =
        new Saml2AuditEvent(Saml2AuditEvents.SAML2_AUDIT_UNRECOVERABLE_ERROR, event.getTimestamp(),
            event.getError().getSpEntityId(), event.getError().getAuthnRequestId(),
            Saml2UnrecoverableErrorAuditData.of(event.getError()));

    log.info("Publishing audit event: {}", auditEvent.getLogString());

    this.publish(auditEvent);
  }

  /**
   * The credential monitoring reports that a credential test has failed. A successful or failed credential reload event
   * will follow.
   */
  @Override
  protected void onFailedCredentialTestEvent(@Nonnull final FailedCredentialTestEvent event) {
    final CredentialAuditEvent auditEvent = CredentialAuditEvent.of(event);
    log.info("Publishing audit event: {}", auditEvent.getLogString());
    this.publish(auditEvent);
  }

  /**
   * The credential monitoring reports that a credential was successfully reloaded (after a failed test).
   */
  @Override
  protected void onSuccessfulCredentialReloadEvent(@Nonnull final SuccessfulCredentialReloadEvent event) {
    final CredentialAuditEvent auditEvent = CredentialAuditEvent.of(event);
    log.info("Publishing audit event: {}", auditEvent.getLogString());
    this.publish(auditEvent);
  }

  /**
   * The credential monitoring reports that a credential failed to be reloaded (after a failed test).
   */
  @Override
  protected void onFailedCredentialReloadEvent(@Nonnull final FailedCredentialReloadEvent event) {
    final CredentialAuditEvent auditEvent = CredentialAuditEvent.of(event);
    log.info("Publishing audit event: {}", auditEvent.getLogString());
    this.publish(auditEvent);
  }

  /**
   * Publishes the {@link Saml2AuditEvent}.
   *
   * @param auditEvent the event to publish
   */
  private void publish(final Saml2AuditEvent auditEvent) {
    this.publisher.publishEvent(new AuditApplicationEvent(auditEvent));
  }

  /**
   * Publishes the {@link CredentialAuditEvent}.
   *
   * @param auditEvent the event to publish
   */
  private void publish(final CredentialAuditEvent auditEvent) {
    this.publisher.publishEvent(new AuditApplicationEvent(auditEvent));
  }

}
