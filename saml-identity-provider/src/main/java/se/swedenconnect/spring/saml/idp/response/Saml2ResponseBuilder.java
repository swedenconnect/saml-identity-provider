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

import java.util.Objects;
import java.util.Optional;

import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.xmlsec.SecurityConfigurationSupport;
import org.opensaml.xmlsec.encryption.EncryptedData;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.springframework.security.config.Customizer;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import se.swedenconnect.opensaml.xmlsec.encryption.support.SAMLObjectEncrypter;
import se.swedenconnect.opensaml.xmlsec.signature.support.SAMLObjectSigner;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.opensaml.OpenSamlCredential;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpError;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpException;
import se.swedenconnect.spring.saml.idp.utils.DefaultSaml2MessageIDGenerator;
import se.swedenconnect.spring.saml.idp.utils.Saml2MessageIDGenerator;

/**
 * Builds a SAML {@link Response} message.
 *
 * @author Martin Lindström
 */
@Slf4j
public class Saml2ResponseBuilder {

  /** The issuer entityID for the {@link Response} objects being created. */
  private final String responseIssuer;

  /** The IdP signing credential. */
  private final OpenSamlCredential signingCredential;

  /** Whether assertions should be encrypted. */
  private boolean encryptAssertions = false;

  /** For encrypting assertions. */
  private SAMLObjectEncrypter samlEncrypter;

  /** For customizing the {@link Response}. */
  private Customizer<Response> responseCustomizer = Customizer.withDefaults();

  /** The ID generator - defaults to {@link DefaultSaml2MessageIDGenerator}. */
  private Saml2MessageIDGenerator idGenerator = new DefaultSaml2MessageIDGenerator();

  /**
   * Constructor.
   * 
   * @param signingCredential the IdP signing credential (for signing of {@link Response} objects)
   */
  public Saml2ResponseBuilder(final String idpEntityId, final PkiCredential signingCredential) {
    this.responseIssuer = Optional.ofNullable(idpEntityId).filter(StringUtils::hasText)
        .orElseThrow(() -> new IllegalArgumentException("idpEntityId must be set"));
    Assert.notNull(signingCredential, "signingCredential must not be null");
    this.signingCredential = OpenSamlCredential.class.isInstance(signingCredential)
        ? OpenSamlCredential.class.cast(signingCredential)
        : new OpenSamlCredential(signingCredential);
  }

  /**
   * Given an error {@link Status} object, the method builds a {@link Response} object indicating the error and signs
   * it.
   * 
   * @param responseAttributes the response attributes needed for building the {@link Response} object
   * @param errorStatus the SAML status object
   * @return a {@link Response} object
   * @throws UnrecoverableSaml2IdpException for errors
   */
  public Response buildErrorResponse(final Saml2ResponseAttributes responseAttributes, final Status errorStatus) {
    Assert.notNull(errorStatus, "errorStatus must not be null");
    final String code = Optional.ofNullable(errorStatus.getStatusCode())
      .map(StatusCode::getValue)
      .orElseThrow(() -> new IllegalArgumentException("Supplied status object does not have status code set"));
    if (StatusCode.SUCCESS.equals(code)) {
      throw new IllegalArgumentException("Can not send error response with status set to success");
    }
    
    final Response response = this.createResponse(responseAttributes, errorStatus);
    this.responseCustomizer.customize(response);
    this.signResponse(response, responseAttributes.getPeerMetadata());

    return response;
  }

  /**
   * Given a {@link Saml2ErrorStatusException} exception, the method builds a {@link Response} object indicating the
   * error {@link Status} given by the exception and signs it.
   * 
   * @param responseAttributes the response attributes needed for building the {@link Response} object
   * @param error the SAML error
   * @return a {@link Response} object
   * @throws UnrecoverableSaml2IdpException for errors
   */
  public Response buildErrorResponse(final Saml2ResponseAttributes responseAttributes, final Saml2ErrorStatusException error)
      throws UnrecoverableSaml2IdpException {    
    return this.buildErrorResponse(responseAttributes, error.getStatus());
  }

  /**
   * Given an {@link Assertion}, the method builds a {@link Response} object including the supplied {@link Assertion}.
   * If the Identity Provider is configured to encrypt assertions, the method encrypts the supplied {@link Assertion}
   * for the recipient given by {@link Saml2ResponseAttributes#getPeerMetadata()}.
   * 
   * @param responseAttributes the response attributes needed for building the {@link Response} object
   * @param assertion the SAML {@link Assertion}
   * @return a {@link Response} object
   * @throws UnrecoverableSaml2IdpException for errors
   */
  public Response buildResponse(final Saml2ResponseAttributes responseAttributes, final Assertion assertion)
      throws UnrecoverableSaml2IdpException {

    final Status status = (Status) XMLObjectSupport.buildXMLObject(Status.DEFAULT_ELEMENT_NAME);
    final StatusCode sc = (StatusCode) XMLObjectSupport.buildXMLObject(StatusCode.DEFAULT_ELEMENT_NAME);
    sc.setValue(StatusCode.SUCCESS);
    status.setStatusCode(sc);

    final Response response = this.createResponse(responseAttributes, status);
    if (this.isEncryptAssertions()) {
      final EncryptedAssertion encryptedAssertion =
          this.encryptAssertion(assertion, responseAttributes.getPeerMetadata());
      response.getEncryptedAssertions().add(encryptedAssertion);
    }
    else {
      response.getAssertions().add(assertion);
    }
    this.responseCustomizer.customize(response);
    this.signResponse(response, responseAttributes.getPeerMetadata());

    return response;
  }

  /**
   * Creates a {@link Response} object with the basic attributes {@code ID}, {@code Destination} and
   * {@code InResponseTo} as well as the {@code Issuer} element and the supplied {@code Status} element.
   * 
   * @param responseAttributes the response attributes needed for building the {@link Response} object
   * @param status the SAML {@link Status} object
   * @return a {@link Response} object
   * @throws UnrecoverableSaml2IdpException for errors
   */
  protected Response createResponse(final Saml2ResponseAttributes responseAttributes, final Status status)
      throws UnrecoverableSaml2IdpException {

    if (responseAttributes.getDestination() == null || responseAttributes.getInResponseTo() == null || status == null) {
      throw new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.INTERNAL, "No response data available");
    }

    final Response samlResponse = (Response) XMLObjectSupport.buildXMLObject(Response.DEFAULT_ELEMENT_NAME);
    samlResponse.setStatus(status);

    samlResponse.setID(this.idGenerator.generateIdentifier());
    samlResponse.setDestination(responseAttributes.getDestination());
    samlResponse.setInResponseTo(responseAttributes.getInResponseTo());
    final Issuer issuer = (Issuer) XMLObjectSupport.buildXMLObject(Issuer.DEFAULT_ELEMENT_NAME);
    issuer.setValue(this.responseIssuer);
    samlResponse.setIssuer(issuer);

    return samlResponse;
  }

  /**
   * Signs the {@link Response} message.
   * 
   * @param samlResponse the object to sign
   * @param peerMetadata the peer metadata (may be used to select signing algorithm)
   * @throws UnrecoverableSaml2IdpException for signing errors
   */
  protected void signResponse(final Response samlResponse, final EntityDescriptor peerMetadata)
      throws UnrecoverableSaml2IdpException {
    try {
      SAMLObjectSigner.sign(samlResponse, this.signingCredential,
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
   * @param peerMetadata the metadata for the peer to whom we encrypt for
   * @return an {@link EncryptedAssertion}
   * @throws UnrecoverableSaml2IdpException for unrecoverable errors
   */
  protected EncryptedAssertion encryptAssertion(final Assertion assertion, final EntityDescriptor peerMetadata)
      throws UnrecoverableSaml2IdpException {

    if (peerMetadata == null) {
      throw new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.INTERNAL, "No response data available");
    }

    try {
      final EncryptedAssertion encryptedAssertion =
          (EncryptedAssertion) XMLObjectSupport.buildXMLObject(EncryptedAssertion.DEFAULT_ELEMENT_NAME);

      final EncryptedData encryptedData =
          this.samlEncrypter.encrypt(assertion, new SAMLObjectEncrypter.Peer(peerMetadata));
      encryptedAssertion.setEncryptedData(encryptedData);

      return encryptedAssertion;
    }
    catch (final EncryptionException e) {
      throw new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.INTERNAL, "Failed to encrypt assertion", e);
    }
  }

  /**
   * Tells whether assertions are encrypted.
   * 
   * @return {@code true} if assertions are encrypted, and {@code false} otherwise
   */
  public boolean isEncryptAssertions() {
    return encryptAssertions;
  }

  /**
   * Assigns whether assertions should be encrypted.
   * 
   * @param encryptAssertions whether assertions should be encrypted
   */
  public void setEncryptAssertions(final boolean encryptAssertions) {
    this.encryptAssertions = encryptAssertions;

    if (this.encryptAssertions) {
      try {
        this.samlEncrypter = new SAMLObjectEncrypter();
      }
      catch (final ComponentInitializationException e) {
        throw new SecurityException("Failed to initialize encrypter", e);
      }
    }
    else {
      this.samlEncrypter = null;
    }
  }

  /**
   * Assigns a custom ID generator. The default is {@link DefaultSaml2MessageIDGenerator}.
   * 
   * @param idGenerator the ID generator
   */
  public void setIdGenerator(final Saml2MessageIDGenerator idGenerator) {
    this.idGenerator = idGenerator;
  }

  /**
   * By assigning a {@link Customizer} the {@link Response} object that is built can be modified. The customizer is
   * invoked when the {@link Response} object has been completely built, but before it is signed.
   * 
   * @param responseCustomizer a {@link Customizer}
   */
  public void setResponseCustomizer(final Customizer<Response> responseCustomizer) {
    this.responseCustomizer = Objects.requireNonNull(responseCustomizer, "responseCustomizer must not be null");
  }

}
