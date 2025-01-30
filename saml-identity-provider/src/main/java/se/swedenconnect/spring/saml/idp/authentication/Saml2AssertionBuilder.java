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
package se.swedenconnect.spring.saml.idp.authentication;

import lombok.extern.slf4j.Slf4j;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.AuthenticatingAuthority;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml.saml2.core.SubjectLocality;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.SecurityConfigurationSupport;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.springframework.security.config.Customizer;
import org.springframework.util.Assert;
import se.swedenconnect.opensaml.common.utils.SamlLog;
import se.swedenconnect.opensaml.xmlsec.signature.support.SAMLObjectSigner;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.opensaml.OpenSamlCredential;
import se.swedenconnect.spring.saml.idp.attributes.release.AttributeReleaseManager;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpError;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpException;
import se.swedenconnect.spring.saml.idp.settings.AssertionSettings;
import se.swedenconnect.spring.saml.idp.utils.DefaultSaml2MessageIDGenerator;
import se.swedenconnect.spring.saml.idp.utils.Saml2MessageIDGenerator;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * The {@code Saml2AssertionBuilder} is responsible for building SAML {@link Assertion}s given
 * {@link Saml2UserAuthentication} objects.
 *
 * @author Martin Lindström
 */
@Slf4j
public class Saml2AssertionBuilder {

  /** The issuer entityID. */
  private final String issuer;

  /** Component that decides which attributes from the user token that should be released in the assertion. */
  private final AttributeReleaseManager attributeReleaseManager;

  /** The IdP signature credential. */
  private final Credential signatureCredential;

  /** For customizing the assertions being created. */
  private Customizer<Assertion> assertionCustomizer = Customizer.withDefaults();

  /**
   * Setting that tells the time restrictions the IdP puts on an Assertion concerning "not on or after". Defaults to
   * {@link AssertionSettings#NOT_ON_OR_AFTER_DURATION_DEFAULT}.
   */
  private Duration notOnOrAfterDuration = AssertionSettings.NOT_ON_OR_AFTER_DURATION_DEFAULT;

  /**
   * Setting that tells the time restrictions the IdP puts on an Assertion concerning "not before". Defaults to
   * {@link AssertionSettings#NOT_BEFORE_DURATION_DEFAULT}.
   */
  private Duration notBeforeDuration = AssertionSettings.NOT_BEFORE_DURATION_DEFAULT;

  /** The ID generator - defaults to {@link DefaultSaml2MessageIDGenerator}. */
  private Saml2MessageIDGenerator idGenerator = new DefaultSaml2MessageIDGenerator();

  /**
   * Constructor.
   *
   * @param idpEntityId the IdP entity ID
   * @param signatureCredential the signature credential (for signing the assertion)
   * @param attributeReleaseManager decides which attributes from the user token that should be released in the
   *     assertion
   */
  public Saml2AssertionBuilder(final String idpEntityId, final PkiCredential signatureCredential,
      final AttributeReleaseManager attributeReleaseManager) {
    Assert.hasText(idpEntityId, "idpEntityId must be set");
    this.issuer = idpEntityId;
    Assert.notNull(signatureCredential, "signatureCredential must not be null");
    this.signatureCredential = new OpenSamlCredential(signatureCredential);
    this.attributeReleaseManager =
        Objects.requireNonNull(attributeReleaseManager, "attributeReleaseManager must not be null");
  }

  /**
   * Given a {@link Saml2UserAuthentication} object a SAML {@link Assertion} is built.
   *
   * @param userAuthentication the information about the user authentication
   * @return an {@link Assertion}
   * @throws Saml2ErrorStatusException for errors that should be reported back to the Service Provider
   * @throws UnrecoverableSaml2IdpException for unrecoverable errors
   */
  public Assertion buildAssertion(final Saml2UserAuthentication userAuthentication)
      throws Saml2ErrorStatusException, UnrecoverableSaml2IdpException {

    final Saml2AuthnRequestAuthenticationToken authnRequestToken =
        Optional.ofNullable(userAuthentication.getAuthnRequestToken())
            .orElseThrow(() -> new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.INTERNAL,
                "No authn request token available in Saml2UserAuthentication", null));

    final Instant now = Instant.now();

    final Assertion assertion = (Assertion) XMLObjectSupport.buildXMLObject(Assertion.DEFAULT_ELEMENT_NAME);

    assertion.setID(this.idGenerator.generateIdentifier());
    assertion.setIssueInstant(now);

    // Issuer
    {
      final Issuer issuer = (Issuer) XMLObjectSupport.buildXMLObject(Issuer.DEFAULT_ELEMENT_NAME);
      issuer.setValue(this.issuer);
      assertion.setIssuer(issuer);
    }

    // Subject
    {
      final Subject subject = (Subject) XMLObjectSupport.buildXMLObject(Subject.DEFAULT_ELEMENT_NAME);
      subject.setNameID(authnRequestToken.getNameIDGenerator().getNameID(userAuthentication));

      final SubjectConfirmation subjectConfirmation =
          (SubjectConfirmation) XMLObjectSupport.buildXMLObject(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
      subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);

      final SubjectConfirmationData subjectConfirmationData =
          (SubjectConfirmationData) XMLObjectSupport.buildXMLObject(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);

      subjectConfirmationData.setAddress(userAuthentication.getSaml2UserDetails().getSubjectIpAddress());
      subjectConfirmationData.setInResponseTo(authnRequestToken.getAuthnRequest().getID());
      subjectConfirmationData.setRecipient(authnRequestToken.getAssertionConsumerServiceUrl());
      subjectConfirmationData.setNotOnOrAfter(now.plus(this.notOnOrAfterDuration));
      subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);

      subject.getSubjectConfirmations().add(subjectConfirmation);
      assertion.setSubject(subject);
    }

    // Conditions
    {
      final Conditions conditions = (Conditions) XMLObjectSupport.buildXMLObject(Conditions.DEFAULT_ELEMENT_NAME);
      conditions.setNotBefore(now.minus(this.notBeforeDuration));
      conditions.setNotOnOrAfter(now.plus(this.notOnOrAfterDuration));

      final AudienceRestriction audienceRestriction =
          (AudienceRestriction) XMLObjectSupport.buildXMLObject(AudienceRestriction.DEFAULT_ELEMENT_NAME);
      final Audience audience = (Audience) XMLObjectSupport.buildXMLObject(Audience.DEFAULT_ELEMENT_NAME);
      audience.setURI(authnRequestToken.getPeerMetadata().getEntityID());
      audienceRestriction.getAudiences().add(audience);
      conditions.getAudienceRestrictions().add(audienceRestriction);

      assertion.setConditions(conditions);
    }

    // AuthnStatement
    {
      final AuthnStatement authnStatement =
          (AuthnStatement) XMLObjectSupport.buildXMLObject(AuthnStatement.DEFAULT_ELEMENT_NAME);
      authnStatement.setAuthnInstant(userAuthentication.getSaml2UserDetails().getAuthnInstant());
      authnStatement.setSessionIndex(assertion.getID());

      final SubjectLocality subjectLocality =
          (SubjectLocality) XMLObjectSupport.buildXMLObject(SubjectLocality.DEFAULT_ELEMENT_NAME);
      subjectLocality.setAddress(userAuthentication.getSaml2UserDetails().getSubjectIpAddress());
      authnStatement.setSubjectLocality(subjectLocality);

      final AuthnContext authnContext =
          (AuthnContext) XMLObjectSupport.buildXMLObject(AuthnContext.DEFAULT_ELEMENT_NAME);
      final AuthnContextClassRef authnContextClassRef =
          (AuthnContextClassRef) XMLObjectSupport.buildXMLObject(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
      authnContextClassRef.setURI(userAuthentication.getSaml2UserDetails().getAuthnContextUri());
      authnContext.setAuthnContextClassRef(authnContextClassRef);

      if (!userAuthentication.getSaml2UserDetails().getAuthenticatingAuthorities().isEmpty()) {
        for (final String aa : userAuthentication.getSaml2UserDetails().getAuthenticatingAuthorities()) {
          final AuthenticatingAuthority authenticatingAuthority =
              (AuthenticatingAuthority) XMLObjectSupport.buildXMLObject(AuthenticatingAuthority.DEFAULT_ELEMENT_NAME);
          authenticatingAuthority.setURI(aa);
          authnContext.getAuthenticatingAuthorities().add(authenticatingAuthority);
        }
      }
      authnStatement.setAuthnContext(authnContext);

      assertion.getAuthnStatements().add(authnStatement);
    }

    // AttributeStatement
    {
      final AttributeStatement attributeStatement =
          (AttributeStatement) XMLObjectSupport.buildXMLObject(AttributeStatement.DEFAULT_ELEMENT_NAME);
      attributeStatement.getAttributes().addAll(this.attributeReleaseManager.releaseAttributes(userAuthentication));
      assertion.getAttributeStatements().add(attributeStatement);
    }

    // Customize ...
    //
    this.assertionCustomizer.customize(assertion);

    log.trace("Issuing Assertion: {}", SamlLog.toStringSafe(assertion));

    // Sign
    {
      final SPSSODescriptor ssoDescriptor =
          authnRequestToken.getPeerMetadata().getSPSSODescriptor(SAMLConstants.SAML20P_NS);
      if (Boolean.TRUE.equals(ssoDescriptor.getWantAssertionsSigned())) {
        try {
          SAMLObjectSigner.sign(assertion, this.signatureCredential,
              SecurityConfigurationSupport.getGlobalSignatureSigningConfiguration(),
              authnRequestToken.getPeerMetadata());

          log.debug("Assertion successfully signed [{}]", authnRequestToken.getLogString());
        }
        catch (final SignatureException e) {
          log.error("Failed to sign Assertion - {} [{}]", e.getMessage(), authnRequestToken.getLogString(), e);
          throw new UnrecoverableSaml2IdpException(
              UnrecoverableSaml2IdpError.INTERNAL, "Failed to sign Assertion", e, userAuthentication);
        }
      }
    }

    return assertion;
  }

  /**
   * By assigning a {@link Customizer} the {@link Assertion} object that is built can be modified. The customizer is
   * invoked when the {@link Assertion} object has been completely built, but before it is signed.
   *
   * @param assertionCustomizer a {@link Customizer}
   */
  public void setAssertionCustomizer(final Customizer<Assertion> assertionCustomizer) {
    this.assertionCustomizer = Objects.requireNonNull(assertionCustomizer, "assertionCustomizer must not be null");
  }

  /**
   * Assigns the setting that tells the time restrictions the IdP puts on an Assertion concerning "not on or after".
   * Defaults to {@link AssertionSettings#NOT_ON_OR_AFTER_DURATION_DEFAULT}.
   *
   * @param notOnOrAfterDuration duration
   */
  public void setNotOnOrAfterDuration(final Duration notOnOrAfterDuration) {
    this.notOnOrAfterDuration = notOnOrAfterDuration;
  }

  /**
   * Assigns the setting that tells the time restrictions the IdP puts on an Assertion concerning "not before". Defaults
   * to {@link AssertionSettings#NOT_BEFORE_DURATION_DEFAULT}.
   *
   * @param notBeforeDuration duration
   */
  public void setNotBeforeDuration(final Duration notBeforeDuration) {
    this.notBeforeDuration = notBeforeDuration;
  }

  /**
   * Assigns a custom ID generator. The default is {@link DefaultSaml2MessageIDGenerator}.
   *
   * @param idGenerator the ID generator
   */
  public void setIdGenerator(final Saml2MessageIDGenerator idGenerator) {
    this.idGenerator = idGenerator;
  }

}
