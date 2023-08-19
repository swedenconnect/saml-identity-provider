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
package se.swedenconnect.spring.saml.idp.error;

import java.util.Collections;
import java.util.Optional;

import org.opensaml.saml.saml2.core.AuthnRequest;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;

import lombok.Getter;
import se.swedenconnect.spring.saml.idp.Saml2IdentityProviderVersion;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthentication;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthenticationInputToken;
import se.swedenconnect.spring.saml.idp.authentication.provider.external.ResumedAuthenticationToken;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;

/**
 * Base class for unrecoverable SAML errors, i.e., such errors that can not be signalled back to the SAML SP.
 * 
 * @author Martin Lindström
 */
public class UnrecoverableSaml2IdpException extends RuntimeException {

  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

  /** The error. */
  private final UnrecoverableSaml2IdpError error;

  /** The ID for the {@link AuthnRequest} message that was processed when the error occurred. */
  private String authnRequestId;

  /** The SAML entityID for the Service Provider that sent the request that was processed when the error occurred. */
  private String spEntityId;

  /**
   * Constructor.
   * 
   * @param authn the current {@link Authentication} object - may be {@code null}
   * @param error the error
   */
  public UnrecoverableSaml2IdpException(final UnrecoverableSaml2IdpError error, final Authentication authn) {
    this(error, null, null, authn);
  }

  /**
   * Constructor.
   * 
   * @param error the error
   * @param msg the message
   */
  public UnrecoverableSaml2IdpException(final UnrecoverableSaml2IdpError error, final String msg,
      final Authentication authn) {
    this(error, msg, null, authn);
  }

  /**
   * Constructor.
   * 
   * @param error the error
   * @param cause the cause of the error
   */
  public UnrecoverableSaml2IdpException(final UnrecoverableSaml2IdpError error, final Throwable cause,
      final Authentication authn) {
    this(error, null, cause, authn);
  }

  /**
   * Constructor.
   * 
   * @param error the error
   * @param msg the message
   * @param cause the cause of the error
   */
  public UnrecoverableSaml2IdpException(final UnrecoverableSaml2IdpError error, final String msg, final Throwable cause,
      final Authentication authn) {
    super(msg != null ? msg : error.getDescription(), cause);
    this.error = error;
    this.setupTraceId(authn);
  }

  /**
   * Gets the specific error.
   * 
   * @return the error
   */
  public UnrecoverableSaml2IdpError getError() {
    return this.error;
  }

  /**
   * Gets the ID for the {@link AuthnRequest} message that was processed when the error occurred.
   * 
   * @return the ID (or {@code null} if not available)
   */
  public String getAuthnRequestId() {
    return this.authnRequestId;
  }

  /**
   * Gets the SAML entityID for the Service Provider that sent the request that was processed when the error occurred.
   * 
   * @return the entityID (or {@code null} if not available)
   */
  public String getSpEntityId() {
    return this.spEntityId;
  }

  /**
   * Given the supplied {@link Authentication} object we save data useful for tracing and logging.
   * 
   * @param authn the {@link Authentication} (may be {@code null})
   */
  private void setupTraceId(final Authentication authn) {
    if (authn == null) {
      return;
    }
    if (authn instanceof Saml2UserAuthentication ua) {
      this.setupTraceId(ua.getAuthnRequestToken());
    }
    else if (authn instanceof Saml2AuthnRequestAuthenticationToken ar) {
      this.authnRequestId = Optional.ofNullable(ar.getAuthnRequest()).map(AuthnRequest::getID).orElse(null);
      this.spEntityId = ar.getEntityId();
    }
    else if (authn instanceof ResumedAuthenticationToken ra) {
      this.setupTraceId(Optional.ofNullable(ra.getAuthnInputToken())
          .map(Saml2UserAuthenticationInputToken::getAuthnRequestToken)
          .orElse(null));
    }
    else if (authn instanceof TraceAuthentication ta) {
      this.authnRequestId = ta.getAuthnRequestId();
      this.spEntityId = ta.getSpEntityId();
    }
  }

  /**
   * Dummy {@link Authentication} class that can be used if no {@link Authentication} object is available but the
   * AuthnRequest ID and SP entityID are known.
   * 
   * @author Martin Lindström
   */
  public static class TraceAuthentication extends AbstractAuthenticationToken {

    private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

    @Getter
    private final String authnRequestId;

    @Getter
    private final String spEntityId;

    /**
     * Constructor.
     * 
     * @param authnRequestId the {@code AuthnRequest} ID
     * @param spEntityId the SP entityID
     */
    public TraceAuthentication(final String authnRequestId, final String spEntityId) {
      super(Collections.emptyList());
      this.setAuthenticated(false);
      this.authnRequestId = authnRequestId;
      this.spEntityId = spEntityId;
    }

    /** {@inheritDoc} */
    @Override
    public Object getCredentials() {
      return null;
    }

    /** {@inheritDoc} */
    @Override
    public Object getPrincipal() {
      return null;
    }

  }

}
