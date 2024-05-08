/*
 * Copyright 2023-2024 Sweden Connect
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

import java.io.Serial;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.opensaml.core.xml.schema.XSURI;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.spring.saml.idp.Saml2IdentityProviderVersion;

/**
 * An audit data element for an {@link AuthnRequest}.
 *
 * @author Martin Lindström
 */
@JsonInclude(Include.NON_EMPTY)
public class Saml2AuthnRequestAuditData extends Saml2AuditData {

  @Serial
  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

  /** The AuthnRequest ID. */
  @Getter
  @Setter
  @JsonProperty(value = "id")
  private String id;

  /** The issuer of the AuthnRequest. */
  @Getter
  @Setter
  @JsonProperty(value = "issuer")
  private String issuer;

  /** Listing of requested "LoA:s". */
  @Getter
  @Setter
  @JsonProperty(value = "authn-context-class-refs")
  private List<String> authnContextClassRefs;

  /** Is "force authn" requested? */
  @Getter
  @Setter
  @JsonProperty(value = "force-authn")
  private boolean forceAuthn;

  /** Is passive authentication requested? */
  @Getter
  @Setter
  @JsonProperty(value = "is-passive")
  private boolean passive;

  /** The relay state. */
  @Getter
  @Setter
  @JsonProperty(value = "relay-state")
  private String relayState;

  /** {@inheritDoc} */
  @Override
  public String getName() {
    return "authn-request";
  }

  /**
   * Creates a {@link Saml2AuthnRequestAuditData} given the {@link AuthnRequest} and relay state.
   *
   * @param authnRequest the {@link AuthnRequest}
   * @param relayState the relay state (or {@code null})
   * @return a {@link Saml2AuthnRequestAuditData}
   */
  public static Saml2AuthnRequestAuditData of(final AuthnRequest authnRequest, final String relayState) {
    if (authnRequest == null) {
      return null;
    }
    final Saml2AuthnRequestAuditData data = new Saml2AuthnRequestAuditData();
    data.setId(authnRequest.getID());
    data.setIssuer(Optional.ofNullable(authnRequest.getIssuer()).map(Issuer::getValue).orElse(null));
    data.setAuthnContextClassRefs(Optional.ofNullable(authnRequest.getRequestedAuthnContext())
        .map(RequestedAuthnContext::getAuthnContextClassRefs)
        .map(refs -> refs.stream()
            .map(XSURI::getURI)
            .collect(Collectors.toList()))
        .orElse(null));
    data.setForceAuthn(Boolean.TRUE.equals(authnRequest.isForceAuthn()));
    data.setPassive(Boolean.TRUE.equals(authnRequest.isPassive()));
    data.setRelayState(relayState);

    return data;
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    return String.format(
        "id='%s', issuer='%s', authn-context-class-refs=%s, force-authn='%s', is-passive='%s', relay-state='%s'",
        this.id, this.issuer, this.authnContextClassRefs, this.forceAuthn, this.passive, this.relayState);
  }

}
