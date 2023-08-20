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
package se.swedenconnect.spring.saml.idp.audit.data;

import java.io.Serializable;
import java.time.Instant;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import se.swedenconnect.spring.saml.idp.Saml2IdentityProviderVersion;
import se.swedenconnect.spring.saml.idp.audit.data.Saml2AssertionAuditData.SamlAttribute;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthentication;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserDetails;

/**
 * Audit data including information about the user authentication.
 *
 * @author Martin Lindström
 */
@JsonInclude(Include.NON_EMPTY)
public class Saml2UserAuthenticationInfoAuditData extends Saml2AuditData {

  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

  /** The authentication instant. */
  @Getter
  @Setter
  @JsonProperty(value = "authn-instant")
  private Instant authnInstant;

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

  /** The SAML attributes delivered by the authenticator - it is not sure that all are relased. */
  @Getter
  @Setter
  @JsonProperty(value = "user-attributes")
  private List<SamlAttribute> userAttributes;

  /** If this was a signature operation, the field tells whether a sign message was displayed. */
  @Getter
  @Setter
  @JsonProperty(value = "sign-message-displayed")
  private Boolean signMessageDisplayed;

  /** Whether this authentication is allowed to be re-used in SSO scenarios. */
  @Getter
  @Setter
  @JsonProperty(value = "allowed-to-reuse")
  private boolean allowedToReuse;

  /** If SSO was applied, this field holds information about the instance when the user was authenticated. */
  @Getter
  @Setter
  @JsonProperty(value = "sso-information")
  private SsoInformation ssoInformation;

  /** {@inheritDoc} */
  @Override
  public String getName() {
    return "user-authentication-info";
  }

  /**
   * Creates a {@link Saml2UserAuthenticationInfoAuditData} based on the supplied {@link Saml2UserAuthentication} token.
   *
   * @param token a {@link Saml2UserAuthentication} object
   * @param signServicePeer if the peer is a sign service
   * @return a {@link Saml2UserAuthenticationInfoAuditData}
   */
  public static Saml2UserAuthenticationInfoAuditData of(
      final Saml2UserAuthentication token, final boolean signServicePeer) {
    if (token == null) {
      return null;
    }
    final Saml2UserAuthenticationInfoAuditData data = new Saml2UserAuthenticationInfoAuditData();
    final Saml2UserDetails details = token.getSaml2UserDetails();
    if (details == null) {
      return null;
    }
    data.setAuthnInstant(details.getAuthnInstant());
    data.setSubjectLocality(details.getSubjectIpAddress());
    data.setAuthnContextClassRef(details.getAuthnContextUri());
    data.setAuthnAuthority(details.getAuthenticatingAuthority());
    if (details.getAttributes() != null) {
      data.setUserAttributes(details.getAttributes().stream()
          .map(ua -> new SamlAttribute(ua.getId(), ua.valuesToString()))
          .toList());
    }
    if (signServicePeer) {
      data.setSignMessageDisplayed(details.isSignMessageDisplayed());
    }
    data.setAllowedToReuse(token.isReuseAuthentication());
    if (token.isSsoApplied()) {
      final Saml2UserAuthentication.AuthenticationInfoTrack track = token.getAuthenticationInfoTrack();
      data.setSsoInformation(
          new SsoInformation(track.getOriginalAuthn().sp(), track.getOriginalAuthn().authnRequestId()));
    }

    return data;
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    final String s = String.format("authn-instant='%s', subject-locality='%s', authn-context-class-ref='%s', "
        + "authn-authority='%s', user-attributes=%s, sign-message-displayed='%s', allowed-to-reuse='%s'",
        this.authnInstant, this.subjectLocality, this.authnContextClassRef, this.authnAuthority, this.userAttributes,
        this.signMessageDisplayed, this.allowedToReuse);
    if (this.ssoInformation != null) {
      return String.format("%s, sso-information=[%s]", s, this.ssoInformation);
    }
    else {
      return s;
    }
  }

  /**
   * If the current authentication object is being re-used, i.e., if SSO was applied, this object holds information
   * about the instance when the user was authenticated.
   */
  @JsonInclude(Include.NON_EMPTY)
  @AllArgsConstructor
  @NoArgsConstructor
  public static class SsoInformation implements Serializable {

    private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

    /**
     * The SAML entityID of the SP that was the requester at the time the user was authenticated.
     */
    @Getter
    @Setter
    @JsonProperty(value = "original-requester")
    private String originalRequester;

    /**
     * The {@code AuthnRequest} ID of the request that led to the user authentication.
     */
    @Getter
    @Setter
    @JsonProperty(value = "original-authn-request-id")
    private String originalAuthnRequestId;

    /** {@inheritDoc} */
    @Override
    public String toString() {
      return String.format("original-requester='%s', original-authn-request-id='%s'",
          this.originalRequester, this.originalAuthnRequestId);
    }

  }

}
