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
package se.swedenconnect.spring.saml.idp.authentication;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

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
import org.springframework.util.StringUtils;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.opensaml.common.utils.SamlLog;
import se.swedenconnect.opensaml.xmlsec.signature.support.SAMLObjectSigner;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.opensaml.OpenSamlCredential;
import se.swedenconnect.spring.saml.idp.attributes.AttributeProducer;
import se.swedenconnect.spring.saml.idp.authnrequest.Saml2AuthnRequestAuthenticationToken;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpError;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpException;
import se.swedenconnect.spring.saml.idp.settings.IdentityProviderSettings;

/**
 * Default implementation of the {@link Saml2AssertionHandler} interface.
 *
 * @author Martin Lindström
 */
@Slf4j
public class DefaultSaml2AssertionHandler implements Saml2AssertionHandler {

  /** The IdP settings. */
  private final IdentityProviderSettings settings;

  /** The IdP signature credential. */
  private final Credential signatureCredential;

  /**
   * Constructor.
   *
   * @param settings the IdP settings
   */
  public DefaultSaml2AssertionHandler(final IdentityProviderSettings settings) {
    this.settings = Objects.requireNonNull(settings, "settings must not be null");

    final PkiCredential cred = Optional.ofNullable(this.settings.getCredentials().getSignCredential())
        .orElseGet(() -> this.settings.getCredentials().getDefaultCredential());
    if (cred == null) {
      throw new IllegalArgumentException("No signature credential available");
    }

    this.signatureCredential = OpenSamlCredential.class.isInstance(cred)
        ? OpenSamlCredential.class.cast(cred)
        : new OpenSamlCredential(cred);

  }

  /** {@inheritDoc} */
  @Override
  public Assertion buildAssertion(
      final Saml2UserAuthentication userAuthentication, final AttributeProducer attributeProducer)
      throws Saml2ErrorStatusException, UnrecoverableSaml2IdpException {

    final Saml2AuthnRequestAuthenticationToken authnRequestToken =
        Optional.ofNullable(userAuthentication.getAuthnRequestToken())
            .orElseThrow(() -> new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.INTERNAL,
                "No authn request token available in Saml2UserAuthentication"));

    final Instant now = Instant.now();

    final Assertion assertion = (Assertion) XMLObjectSupport.buildXMLObject(Assertion.DEFAULT_ELEMENT_NAME);

    assertion.setID(UUID.randomUUID().toString()); // TODO: Use something else
    assertion.setIssueInstant(now);

    // Issuer
    {
      final Issuer issuer = (Issuer) XMLObjectSupport.buildXMLObject(Issuer.DEFAULT_ELEMENT_NAME);
      issuer.setValue(this.settings.getEntityId());
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
      subjectConfirmationData.setNotOnOrAfter(now.plus(this.settings.getAssertionSettings().getNotOnOrAfterDuration()));
      subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);

      subject.getSubjectConfirmations().add(subjectConfirmation);
      assertion.setSubject(subject);
    }

    // Conditions
    {
      final Conditions conditions = (Conditions) XMLObjectSupport.buildXMLObject(Conditions.DEFAULT_ELEMENT_NAME);
      conditions.setNotBefore(now.minus(this.settings.getAssertionSettings().getNotBeforeDuration()));
      conditions.setNotOnOrAfter(now.plus(this.settings.getAssertionSettings().getNotOnOrAfterDuration()));

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

      if (StringUtils.hasText(userAuthentication.getSaml2UserDetails().getAuthenticatingAuthority())) {
        final AuthenticatingAuthority authenticatingAuthority =
            (AuthenticatingAuthority) XMLObjectSupport.buildXMLObject(AuthenticatingAuthority.DEFAULT_ELEMENT_NAME);
        authenticatingAuthority.setURI(userAuthentication.getSaml2UserDetails().getAuthenticatingAuthority());
        authnContext.getAuthenticatingAuthorities().add(authenticatingAuthority);
      }
      authnStatement.setAuthnContext(authnContext);

      assertion.getAuthnStatements().add(authnStatement);
    }

    // AttributeStatement
    {
      final AttributeStatement attributeStatement =
          (AttributeStatement) XMLObjectSupport.buildXMLObject(AttributeStatement.DEFAULT_ELEMENT_NAME);
      attributeStatement.getAttributes().addAll(attributeProducer.releaseAttributes(userAuthentication));
      assertion.getAttributeStatements().add(attributeStatement);
    }

    log.trace("Issuing Assertion: {}", SamlLog.toStringSafe(assertion));

    // Sign
    {
      final SPSSODescriptor ssoDescriptor =
          authnRequestToken.getPeerMetadata().getSPSSODescriptor(SAMLConstants.SAML20P_NS);
      if (ssoDescriptor.getWantAssertionsSigned()) {
        try {
          SAMLObjectSigner.sign(assertion, this.signatureCredential,
              SecurityConfigurationSupport.getGlobalSignatureSigningConfiguration(),
              authnRequestToken.getPeerMetadata());

          log.debug("Assertion successfully signed {}", authnRequestToken.getLogString());
        }
        catch (final SignatureException e) {
          log.error("Failed to sign Assertion - {} {}", e.getMessage(), authnRequestToken.getLogString(), e);
          throw new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.INTERNAL, "Failed to sign Assertion", e);
        }
      }
    }

    return assertion;
  }

}
