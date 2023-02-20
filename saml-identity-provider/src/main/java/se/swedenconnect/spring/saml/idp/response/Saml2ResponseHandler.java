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
package se.swedenconnect.spring.saml.idp.response;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.SecurityConfigurationSupport;
import org.opensaml.xmlsec.encryption.EncryptedData;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.util.StringUtils;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.codec.Base64Support;
import net.shibboleth.utilities.java.support.codec.EncodingException;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import se.swedenconnect.opensaml.common.utils.SamlLog;
import se.swedenconnect.opensaml.xmlsec.encryption.support.SAMLObjectEncrypter;
import se.swedenconnect.opensaml.xmlsec.signature.support.SAMLObjectSigner;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.opensaml.OpenSamlCredential;
import se.swedenconnect.spring.saml.idp.context.Saml2IdpContextHolder;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpError;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpException;
import se.swedenconnect.spring.saml.idp.settings.IdentityProviderSettings;

/**
 * A handler for sending SAML {@link Response} messages.
 * 
 * @author Martin Lindström
 */
@Slf4j
public class Saml2ResponseHandler {

  /** For internal use. */
  private static final String RESPONSE_PARAMETERS_SESSION_NAME =
      Saml2ResponseHandler.class.getPackageName() + "." + ResponseParameters.class.getSimpleName();

  /** The IdP settings. */
  private final IdentityProviderSettings settings;

  /** Custom response page. */
  private SamlResponseEntryPoint responsePageEntryPoint;

  /** The IdP signature credential. */
  private Credential signatureCredential;

  /** For encrypting assertions. */
  private final SAMLObjectEncrypter samlEncrypter;

  /**
   * Constructor.
   * 
   * @param settings the IdP settings
   */
  public Saml2ResponseHandler(final IdentityProviderSettings settings) {
    this.settings = Objects.requireNonNull(settings, "settings must not be null");

    final PkiCredential cred = Optional.ofNullable(this.settings.getCredentials().getSignCredential())
        .orElseGet(() -> this.settings.getCredentials().getDefaultCredential());
    if (cred == null) {
      throw new IllegalArgumentException("No signature credential available");
    }

    this.signatureCredential = OpenSamlCredential.class.isInstance(cred)
        ? OpenSamlCredential.class.cast(cred)
        : new OpenSamlCredential(cred);

    try {
      this.samlEncrypter = new SAMLObjectEncrypter();
    }
    catch (final ComponentInitializationException e) {
      throw new SecurityException("Failed to initialize encrypter", e);
    }
  }

  /**
   * Sends a SAML response including the supplied {@link Assertion}.
   * <p>
   * If the IdP is configured to encrypt assertions, the supplied assertion will be encrypted for the recipient.
   * </p>
   * 
   * @param request the HTTP servlet request
   * @param response the HTTP servlet response
   * @param assertion the {@link Assertion} to include in the response
   * @throws UnrecoverableSaml2IdpException for send errors
   */
  public void sendSamlResponse(
      final HttpServletRequest request, final HttpServletResponse response, final Assertion assertion)
      throws UnrecoverableSaml2IdpException {

    final Response samlResponse = (Response) XMLObjectSupport.buildXMLObject(Response.DEFAULT_ELEMENT_NAME);

    final Status status = (Status) XMLObjectSupport.buildXMLObject(Status.DEFAULT_ELEMENT_NAME);
    final StatusCode sc = (StatusCode) XMLObjectSupport.buildXMLObject(StatusCode.DEFAULT_ELEMENT_NAME);
    sc.setValue(StatusCode.SUCCESS);
    status.setStatusCode(sc);
    samlResponse.setStatus(status);

    if (this.settings.getAssertionSettings().getEncryptAssertions()) {
      log.debug("IdP is configured to encrypt assertions, encrypting '{}' ...", assertion.getID());

      final EncryptedAssertion encryptedAssertion = this.encryptAssertion(assertion);
      samlResponse.getEncryptedAssertions().add(encryptedAssertion);
    }
    else {
      samlResponse.getAssertions().add(assertion);
    }

    this.sendSamlResponse(samlResponse, request, response);
  }

  /**
   * Sends a SAML error {@link Response} message.
   * 
   * @param request the HTTP servlet request
   * @param response the HTTP servlet response
   * @param error the SAML error
   * @throws UnrecoverableSaml2IdpException for send errors
   */
  public void sendErrorResponse(
      final HttpServletRequest request, final HttpServletResponse response, final Saml2ErrorStatusException error)
      throws UnrecoverableSaml2IdpException {

    final Response samlResponse = (Response) XMLObjectSupport.buildXMLObject(Response.DEFAULT_ELEMENT_NAME);
    samlResponse.setStatus(error.getStatus());

    this.sendSamlResponse(samlResponse, request, response);
  }

  /**
   * Sends a SAML {@link Response} message.
   * 
   * @param samlResponse the {@link Response} message to fill in, and send
   * @param request the HTTP servlet request
   * @param response the HTTP servlet response
   * @param error the SAML error
   * @throws UnrecoverableSaml2IdpException for send errors
   */
  private void sendSamlResponse(
      final Response samlResponse, final HttpServletRequest request, final HttpServletResponse response)
      throws UnrecoverableSaml2IdpException {

    // Make sure that we know where to send the Response message ...
    //
    final Saml2ResponseAttributes responseAttributes = Saml2IdpContextHolder.getContext().getResponseAttributes();
    if (responseAttributes.getDestination() == null || responseAttributes.getInResponseTo() == null) {
      throw new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.INTERNAL, "No response data available");
    }

    // Build Response message
    //
    samlResponse.setID(UUID.randomUUID().toString()); // TODO
    samlResponse.setDestination(responseAttributes.getDestination());
    samlResponse.setInResponseTo(responseAttributes.getInResponseTo());
    final Issuer issuer = (Issuer) XMLObjectSupport.buildXMLObject(Issuer.DEFAULT_ELEMENT_NAME);
    issuer.setValue(this.settings.getEntityId());
    samlResponse.setIssuer(issuer);

    // Sign the Response
    //
    this.signResponse(samlResponse, responseAttributes.getPeerMetadata());

    // Marshall and encode ...
    //
    final String encodedSamlResponse = this.encodeResponse(samlResponse);

    log.trace("Sending SAML Response: {}", SamlLog.toStringSafe(samlResponse));

    // Post the response ...
    //
    this.postResponse(request, response, responseAttributes.getDestination(),
        encodedSamlResponse, responseAttributes.getRelayState());
  }

  /**
   * Signs the {@link Response} message.
   * 
   * @param samlResponse the object to sign
   * @param peerMetadata the peer metadata (may be used to select signing algorithm)
   * @throws UnrecoverableSaml2IdpException for signing errors
   */
  private void signResponse(final Response samlResponse, final EntityDescriptor peerMetadata)
      throws UnrecoverableSaml2IdpException {
    try {
      SAMLObjectSigner.sign(samlResponse, this.signatureCredential,
          SecurityConfigurationSupport.getGlobalSignatureSigningConfiguration(), peerMetadata);

      log.debug("Response message successfully signed [destination: '{}', id: '{}', in-response-to: {}]",
          samlResponse.getDestination(), samlResponse.getID(), samlResponse.getInResponseTo());
    }
    catch (final SignatureException e) {
      log.error("Failed to sign Response message - {} [destination: '{}', id: '{}', in-response-to: {}]",
          e.getMessage(), samlResponse.getDestination(), samlResponse.getID(), samlResponse.getInResponseTo(), e);

      throw new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.INTERNAL,
          "Failed to sign Response message", e);
    }
  }

  /**
   * Encrypts the supplied {@link Assertion}.
   * 
   * @param assertion the assertion to encrypt
   * @return an {@link EncryptedAssertion}
   * @throws UnrecoverableSaml2IdpException for unrecoverable errors
   */
  private EncryptedAssertion encryptAssertion(final Assertion assertion) throws UnrecoverableSaml2IdpException {
    try {
      final EncryptedAssertion encryptedAssertion =
          (EncryptedAssertion) XMLObjectSupport.buildXMLObject(EncryptedAssertion.DEFAULT_ELEMENT_NAME);

      final Saml2ResponseAttributes responseAttributes = Saml2IdpContextHolder.getContext().getResponseAttributes();
      if (responseAttributes.getPeerMetadata() == null) {
        throw new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.INTERNAL, "No response data available");
      }

      final EncryptedData encryptedData =
          this.samlEncrypter.encrypt(assertion, new SAMLObjectEncrypter.Peer(responseAttributes.getPeerMetadata()));
      encryptedAssertion.setEncryptedData(encryptedData);

      return encryptedAssertion;

    }
    catch (final EncryptionException e) {
      throw new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.INTERNAL, "Failed to encrypt assertion", e);
    }
  }

  /**
   * Encodes the supplied {@link Response} message for being included in a HTML form.
   * 
   * @param samlResponse the response message
   * @return the Base64-encoding of the message
   * @throws UnrecoverableSaml2IdpException for encoding errors
   */
  private String encodeResponse(final Response samlResponse) throws UnrecoverableSaml2IdpException {
    try {
      final String xml = SerializeSupport.nodeToString(XMLObjectSupport.marshall(samlResponse));
      return Base64Support.encode(xml.getBytes(StandardCharsets.UTF_8), Base64Support.UNCHUNKED);
    }
    catch (final MarshallingException | EncodingException e) {
      log.error("Failed to encode Response message - {} [destination: '{}', id: '{}', in-response-to: {}]",
          e.getMessage(), samlResponse.getDestination(), samlResponse.getID(), samlResponse.getInResponseTo(), e);

      throw new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.INTERNAL,
          "Failed to encode Response message", e);
    }
  }

  /**
   * Posts the response to the Service Provider via the user agent.
   * 
   * @param request the HTTP servlet request
   * @param response the HTTP servlet response
   * @param destination the destination URL
   * @param encodedSamlResponse the encoded SAML response message
   * @param relayState the RelayState variable (may be null)
   * @throws UnrecoverableSaml2IdpException for send errors
   */
  private void postResponse(final HttpServletRequest request, final HttpServletResponse response,
      final String destination, final String encodedSamlResponse, final String relayState)
      throws UnrecoverableSaml2IdpException {

    try {
      if (this.responsePageEntryPoint != null) {
        // Save the parameters in the session. Will be removed by the SamlResponseEntryPoint
        // when redirecting to the response page.
        //
        request.getSession().setAttribute(RESPONSE_PARAMETERS_SESSION_NAME,
            new ResponseParameters(destination, encodedSamlResponse, relayState));

        this.responsePageEntryPoint.commence(request, response, null);
      }
      else {
        DefaultResponsePage.sendResponse(response, destination, encodedSamlResponse, relayState);
      }
    }
    catch (final IOException | ServletException e) {
      log.error("Failed to send SAML Response to {} - {}", destination, e.getMessage(), e);
      throw new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.INTERNAL,
          "Failed to send Response message", e);
    }
  }

  /**
   * Assigns a custom response page.
   * 
   * @param responsePage the page that generates the HTML for the POST form
   */
  public void setResponsePage(final String responsePage) {
    if (responsePage == null) {
      this.responsePageEntryPoint = null;
      return;
    }
    this.responsePageEntryPoint = new SamlResponseEntryPoint(responsePage);
    this.responsePageEntryPoint.setForceHttps(true);
    this.responsePageEntryPoint.setUseForward(true);
    this.responsePageEntryPoint.afterPropertiesSet();
  }

  /**
   * Internal class for temporarily store the response parameters in the session.
   */
  @AllArgsConstructor
  private static class ResponseParameters {
    @Getter
    private String destination;

    @Getter
    private String samlResponse;

    @Getter
    private String relayState;
  }

  /**
   * A customization of the {@link LoginUrlAuthenticationEntryPoint} that we use to redirect the user agent to the
   * configured response page.
   * 
   * @author Martin Lindström
   */
  private static class SamlResponseEntryPoint extends LoginUrlAuthenticationEntryPoint {

    public SamlResponseEntryPoint(final String destination) {
      super(destination);
    }

    /**
     * Prepares for redirecting to the configured response page by appending the response parameters as query paremeters
     * to the configured response page URL.
     */
    @Override
    protected String determineUrlToUseForThisRequest(
        final HttpServletRequest request, final HttpServletResponse response, final AuthenticationException exception) {
      final String url = super.determineUrlToUseForThisRequest(request, response, exception);

      final HttpSession session = request.getSession();
      final ResponseParameters responseParameters =
          (ResponseParameters) session.getAttribute(RESPONSE_PARAMETERS_SESSION_NAME);
      if (responseParameters == null) {
        log.error("Missing response parameters - redirect to custom response page will fail");
        return url;
      }

      // Clear the session, we don't need the parameters anymore.
      session.removeAttribute(RESPONSE_PARAMETERS_SESSION_NAME);

      StringBuilder sb = new StringBuilder(url);
      sb.append(url.contains("?") ? '&' : '?').append("destination=")
          .append(URLEncoder.encode(responseParameters.getDestination(), StandardCharsets.UTF_8))
          .append("&SAMLResponse=")
          .append(URLEncoder.encode(responseParameters.getSamlResponse(), StandardCharsets.UTF_8));
      if (StringUtils.hasText(responseParameters.getRelayState())) {
        sb.append("&RelayState=" + URLEncoder.encode(responseParameters.getRelayState(), StandardCharsets.UTF_8));
      }

      return sb.toString();
//      final UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(url)
//          .queryParam("destination", responseParameters.getDestination())
//          .queryParam("SAMLResponse", responseParameters.getSamlResponse())
//          .queryParamIfPresent("RelayState", Optional.ofNullable(responseParameters.getRelayState()));
//          
//      return builder.toUriString();
    }

  }
}
