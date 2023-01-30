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
package se.swedenconnect.spring.saml.idp.authnrequest;

import java.util.Collections;
import java.util.Optional;

import org.opensaml.saml.common.messaging.context.SAMLBindingContext;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;

import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.spring.saml.idp.utils.SerializableOpenSamlObject;

/**
 * An {@link Authentication} object for a SAML authentication request.
 *
 * @author Martin Lindström
 */
public class Saml2AuthnRequestAuthenticationToken extends AbstractAuthenticationToken {

  private static final long serialVersionUID = 967806521331894053L;

  private final SerializableOpenSamlObject<AuthnRequest> authnRequest;
  private final String relayState;

  private SerializableOpenSamlObject<EntityDescriptor> peerMetadata;

  /** For OpenSAML operations. */
  @Setter
  @Getter
  private transient SAMLBindingContext samlBindingContext;

  public Saml2AuthnRequestAuthenticationToken(final AuthnRequest authnRequest, final String relayState) {
    super(Collections.emptyList());
    this.authnRequest = new SerializableOpenSamlObject<AuthnRequest>(authnRequest, AuthnRequest.class);
    this.relayState = relayState;
    this.setAuthenticated(false);
  }

  @Override
  public Object getCredentials() {
    return "";
  }

  @Override
  public Object getPrincipal() {
    return authnRequest.get().getIssuer().getValue();
  }

  public void setPeerMetadata(final EntityDescriptor peerMetadata) {
    this.peerMetadata = new SerializableOpenSamlObject<EntityDescriptor>(peerMetadata, EntityDescriptor.class);
  }

  public EntityDescriptor getPeerMetadata() {
    return Optional.ofNullable(this.peerMetadata).map(SerializableOpenSamlObject::get).orElse(null);
  }

}
