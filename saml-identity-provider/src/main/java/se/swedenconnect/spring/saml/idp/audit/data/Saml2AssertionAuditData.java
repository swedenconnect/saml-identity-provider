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
package se.swedenconnect.spring.saml.idp.audit.data;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AuthenticatingAuthority;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml.saml2.core.SubjectLocality;
import se.swedenconnect.spring.saml.idp.Saml2IdentityProviderVersion;
import se.swedenconnect.spring.saml.idp.attributes.UserAttribute;

import java.io.Serial;
import java.io.Serializable;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Audit data for a SAML {@code Assertion}.
 *
 * @author Martin Lindström
 */
@JsonInclude(Include.NON_EMPTY)
public class Saml2AssertionAuditData extends Saml2AuditData {

  @Serial
  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

  /** The assertion ID. */
  @Getter
  @Setter
  @JsonProperty(value = "id")
  private String id;

  /** Holds the ID for the corresponding AuthnRequest. */
  @Getter
  @Setter
  @JsonProperty(value = "in-response-to")
  private String inResponseTo;

  /** Whether the assertion is signed. */
  @Getter
  @Setter
  @JsonProperty(value = "is-signed")
  private boolean signed;

  /** Whether the assertion is encrypted. */
  @Getter
  @Setter
  @JsonProperty(value = "is-encrypted")
  private boolean encrypted;

  /** The issuance time for the assertion. */
  @Getter
  @Setter
  @JsonProperty(value = "issued-at")
  private Instant issuedAt;

  /** The entityID of the issuing entity. */
  @Getter
  @Setter
  @JsonProperty(value = "issuer")
  private String issuer;

  /** The authentication instant. */
  @Getter
  @Setter
  @JsonProperty(value = "authn-instant")
  private Instant authnInstant;

  /** The subject's (assigned) ID. */
  @Getter
  @Setter
  @JsonProperty(value = "subject-id")
  private String subjectId;

  /** The subject locality (IP). */
  @Getter
  @Setter
  @JsonProperty(value = "subject-locality")
  private String subjectLocality;

  /** The LoA URI (level of assurance). */
  @Getter
  @Setter
  @JsonProperty(value = "authn-context-class-ref")
  private String authnContextClassRef;

  /** Optional ID for authenticating authority. */
  @Getter
  @Setter
  @JsonProperty(value = "authn-authority")
  private String authnAuthority;

  /** The SAML attributes. */
  @Getter
  @Setter
  @JsonProperty(value = "attributes")
  private List<SamlAttribute> attributes;

  /** {@inheritDoc} */
  @Override
  public String getName() {
    return "saml-assertion";
  }

  /**
   * Creates a {@link Saml2AssertionAuditData} given an {@link Assertion}.
   *
   * @param assertion the SAML assertion
   * @param encrypted whether this assertion is encrypted (when placed in response)
   * @return a {@link Saml2AssertionAuditData}
   */
  public static Saml2AssertionAuditData of(final Assertion assertion, final boolean encrypted) {
    if (assertion == null) {
      return null;
    }
    final Saml2AssertionAuditData data = new Saml2AssertionAuditData();
    data.setId(assertion.getID());
    data.setSigned(assertion.isSigned());
    data.setEncrypted(encrypted);
    data.setIssuedAt(assertion.getIssueInstant());
    data.setIssuer(Optional.ofNullable(assertion.getIssuer()).map(Issuer::getValue).orElse(null));

    final Subject subject = assertion.getSubject();
    if (subject != null) {
      data.setSubjectId(Optional.ofNullable(subject.getNameID()).map(NameID::getValue).orElse(null));
      data.setInResponseTo(
          subject.getSubjectConfirmations().stream()
              .map(SubjectConfirmation::getSubjectConfirmationData)
              .filter(Objects::nonNull)
              .map(SubjectConfirmationData::getInResponseTo)
              .findFirst()
              .orElse(null));
    }
    final AuthnStatement authnStatement = assertion.getAuthnStatements().stream().findFirst().orElse(null);
    if (authnStatement != null) {
      data.setAuthnInstant(authnStatement.getAuthnInstant());
      data.setSubjectLocality(Optional.ofNullable(authnStatement.getSubjectLocality())
          .map(SubjectLocality::getAddress)
          .orElse(null));
      data.setAuthnContextClassRef(Optional.ofNullable(authnStatement.getAuthnContext())
          .map(AuthnContext::getAuthnContextClassRef)
          .map(AuthnContextClassRef::getURI)
          .orElse(null));
      data.setAuthnAuthority(Optional.ofNullable(authnStatement.getAuthnContext())
          .map(AuthnContext::getAuthenticatingAuthorities)
          .flatMap(a -> a.stream().map(AuthenticatingAuthority::getURI).findFirst())
          .orElse(null));
    }
    assertion.getAttributeStatements().stream().findFirst()
        .ifPresent(attributeStatement -> data.setAttributes(attributeStatement.getAttributes().stream()
            .map(a -> new SamlAttribute(a.getName(), getAttributeValue(a)))
            .toList()));

    return data;
  }

  /**
   * Gets attribute value as a string. If multivalued, the first value is read.
   *
   * @param attribute the attribute
   * @return value as a String
   */
  protected static String getAttributeValue(final Attribute attribute) {
    try {
      final UserAttribute userAttribute = new UserAttribute(attribute);
      return userAttribute.getStringValues().stream().findFirst().orElse(null);
    }
    catch (final Exception e) {
      return null;
    }
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return String.format(
        "id='%s', in-response-to='%s', is-signed='%s', is-encrypted='%s', issued-at='%s', issuer='%s', subject-id='%s'"
            + ", authn-instant='%s', subject-locality='%s', authn-context-class-ref='%s', authn-authority='%s', attributes=%s",
        this.id, this.inResponseTo, this.signed, this.encrypted, this.issuedAt, this.issuer, this.subjectId,
        this.authnInstant, this.subjectLocality, this.authnContextClassRef, this.authnAuthority, this.attributes);
  }

  /**
   * Representation of a SAML attribute.
   */
  @JsonInclude(Include.NON_EMPTY)
  @AllArgsConstructor
  @NoArgsConstructor
  public static class SamlAttribute implements Serializable {

    @Serial
    private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

    /** The attribute name. */
    @Getter
    @Setter
    @JsonProperty(value = "name")
    private String name;

    /** The attribute value. */
    @Getter
    @Setter
    @JsonProperty(value = "value")
    private String value;

    /** {@inheritDoc} */
    @Override
    public String toString() {
      return String.format("%s='%s'", this.name, this.value);
    }

  }
}
