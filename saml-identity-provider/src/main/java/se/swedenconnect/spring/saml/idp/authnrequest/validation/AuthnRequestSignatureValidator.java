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
package se.swedenconnect.spring.saml.idp.authnrequest.validation;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.shared.component.ComponentInitializationException;
import net.shibboleth.shared.primitive.NonnullSupplier;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.messaging.handler.MessageHandlerException;
import org.opensaml.saml.common.binding.security.impl.SAMLProtocolMessageXMLSignatureSecurityHandler;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.binding.security.impl.SAML2HTTPRedirectDeflateSignatureSecurityHandler;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.xmlsec.SignatureValidationConfiguration;
import org.opensaml.xmlsec.SignatureValidationParameters;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.signature.support.SignatureTrustEngine;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.util.StringUtils;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;
import se.swedenconnect.spring.saml.idp.context.Saml2IdpContextHolder;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpError;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpException;
import se.swedenconnect.spring.saml.idp.utils.OpenSamlUtils;

import java.util.Objects;

/**
 * Implementation of a {@link AuthnRequestValidator} using OpenSAML mechanisms to verify the signature of the
 * {@code AuthnRequest}.
 *
 * @author Martin Lindström
 */
@Slf4j
public class AuthnRequestSignatureValidator implements AuthnRequestValidator {

  /** The signature trust engine. */
  private final SignatureTrustEngine signatureTrustEngine;

  /** Checks signature on AuthnRequest (if POST binding). */
  private final SAMLProtocolMessageXMLSignatureSecurityHandler xmlSignatureSecurityHandler;

  /** Checks signature on AuthnRequest (if redirect binding). */
  private final SAML2HTTPRedirectDeflateSignatureSecurityHandler httpRedirectDeflateSignatureSecurityHandler;

  /** Access to the current HttpServletRequest. */
  private final NonnullSupplier<HttpServletRequest> httpServletRequest;

  /**
   * Constructor.
   *
   * @param signatureTrustEngine the OpenSAML signature trust engine used to verify signatures
   */
  public AuthnRequestSignatureValidator(final SignatureTrustEngine signatureTrustEngine) {
    this.signatureTrustEngine = Objects.requireNonNull(signatureTrustEngine, "signatureTrustEngine must not be null");
    try {
      this.httpServletRequest = OpenSamlUtils.getHttpServletRequestSupplier();
      this.xmlSignatureSecurityHandler = new SAMLProtocolMessageXMLSignatureSecurityHandler();
      this.xmlSignatureSecurityHandler.initialize();
      this.httpRedirectDeflateSignatureSecurityHandler = new SAML2HTTPRedirectDeflateSignatureSecurityHandler();
      this.httpRedirectDeflateSignatureSecurityHandler.setHttpServletRequestSupplier(this.httpServletRequest);
      this.httpRedirectDeflateSignatureSecurityHandler.initialize();
    }
    catch (final ComponentInitializationException e) {
      throw new InternalAuthenticationServiceException("Failed to initialize OpenSAML beans", e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public void validate(final Saml2AuthnRequestAuthenticationToken token) throws UnrecoverableSaml2IdpException {

    if (!this.isSigned(token)) {
      if (this.isSignedAuthnRequestRequired(token)) {
        final String msg = "Authentication request is required to be signed, but is not";
        log.info("{} [entity-id: {}, authn-request: {}]",
            msg, token.getPeerMetadata().getEntityID(), token.getAuthnRequest().getID());
        throw new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.MISSING_AUTHNREQUEST_SIGNATURE, token);
      }
    }

    // Update OpenSAML context for signature validation ...
    //
    token.getMessageContext().addSubcontext(this.createSecurityParametersContext());

    try {
      if (SAMLConstants.SAML2_REDIRECT_BINDING_URI.equals(token.getBindingUri())) {
        this.httpRedirectDeflateSignatureSecurityHandler.invoke(token.getMessageContext());
      }
      else {
        this.xmlSignatureSecurityHandler.invoke(token.getMessageContext());
      }
    }
    catch (final MessageHandlerException e) {
      final String msg = String.format("Authentication request signature validation failed - %s", e.getMessage());
      log.info("{} [entity-id: {}, authn-request: {}]",
          msg, token.getPeerMetadata().getEntityID(), token.getAuthnRequest().getID());
      log.debug("", e);
      throw new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.INVALID_AUTHNREQUEST_SIGNATURE, msg, e,
          token);
    }

    log.debug("Authentication request signature validation was successful [entity-id: {}, authn-request: {}]",
        token.getPeerMetadata().getEntityID(), token.getAuthnRequest().getID());
  }

  /**
   * Predicate that tells whether the received authentication request was signed.
   *
   * @param token the authentication request token
   * @return {@code true} if the authentication request was signed, and {@code false} otherwise
   */
  protected boolean isSigned(final Saml2AuthnRequestAuthenticationToken token) {
    if (SAMLConstants.SAML2_REDIRECT_BINDING_URI.equals(token.getBindingUri())) {
      final String signature = this.httpServletRequest.get().getParameter("Signature");
      return StringUtils.hasText(signature);
    }
    else {
      return token.getAuthnRequest().isSigned();
    }
  }

  /**
   * Given the IdP settings, and possibly also the SP {@link EntityDescriptor} we determine whether the received
   * {@link AuthnRequest} is required to be signed.
   *
   * @param token the token
   * @return {@code true} if the {@link AuthnRequest} must be signed, and {@code false} otherwise
   */
  protected boolean isSignedAuthnRequestRequired(final Saml2AuthnRequestAuthenticationToken token) {
    if (Saml2IdpContextHolder.getContext().getSettings().getRequiresSignedRequests()) {
      return true;
    }
    return Boolean.TRUE.equals(
        token.getPeerMetadata().getSPSSODescriptor(SAMLConstants.SAML20P_NS).isAuthnRequestsSigned());
  }

  /**
   * Creates an OpenSAML {@link SecurityParametersContext} used during signature validation.
   *
   * @return a {@link SecurityParametersContext}
   */
  private SecurityParametersContext createSecurityParametersContext() {
    final SignatureValidationConfiguration globalOpenSamlConfig =
        ConfigurationService.get(SignatureValidationConfiguration.class);

    final SignatureValidationParameters signatureValidationParameters = new SignatureValidationParameters();
    signatureValidationParameters.setExcludedAlgorithms(globalOpenSamlConfig.getExcludedAlgorithms());
    signatureValidationParameters.setIncludedAlgorithms(globalOpenSamlConfig.getIncludedAlgorithms());
    signatureValidationParameters.setSignatureTrustEngine(this.signatureTrustEngine);

    final SecurityParametersContext securityParametersContext = new SecurityParametersContext();
    securityParametersContext.setSignatureValidationParameters(signatureValidationParameters);
    return securityParametersContext;
  }

}
