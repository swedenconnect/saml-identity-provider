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
import java.util.Objects;
import java.util.Optional;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.common.messaging.context.SAMLBindingContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;

import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorUtils;
import se.swedenconnect.opensaml.sweid.saml2.metadata.entitycategory.EntityCategoryConstants;
import se.swedenconnect.spring.saml.idp.Saml2IdentityProviderVersion;
import se.swedenconnect.spring.saml.idp.attributes.nameid.NameIDGenerator;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpError;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpException;
import se.swedenconnect.spring.saml.idp.utils.SerializableOpenSamlObject;

/**
 * An {@link Authentication} object for a SAML authentication request. This token will act as the input for the user
 * authentication process.
 *
 * @author Martin Lindström
 */
public class Saml2AuthnRequestAuthenticationToken extends AbstractAuthenticationToken {

  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

  /** The AuthnRequest that was received. */
  private final SerializableOpenSamlObject<AuthnRequest> authnRequest;

  /** The RelayState. */
  private final String relayState;

  /** The peer (SP) metadata. */
  private SerializableOpenSamlObject<EntityDescriptor> peerMetadata;

  /** The assertion consumer servuce URL to use when posting back an assertion. */
  private String assertionConsumerServiceUrl;

  /**
   * The {@link NameIDGenerator} to use when generating a {@code NameID} in the assertion that is created based on this
   * request.
   */
  private NameIDGenerator nameIDGenerator;

  /** For OpenSAML operations. */
  @Setter
  @Getter
  private transient MessageContext messageContext;

  /**
   * Constructor assigning the received {@link AuthnRequest} and optionally also the {@code RelayState} variable.
   *
   * @param authnRequest the SAML authentication request
   * @param relayState the {@code RelayState} variable
   */
  public Saml2AuthnRequestAuthenticationToken(final AuthnRequest authnRequest, final String relayState) {
    super(Collections.emptyList());
    this.authnRequest = new SerializableOpenSamlObject<>(authnRequest);
    this.relayState = relayState;
    this.setAuthenticated(false);
  }

  /**
   * Will always return an empty string.
   */
  @Override
  public Object getCredentials() {
    return "";
  }

  /**
   * The principal of this token is the issuer entityID of the {@code AuthnRequest}.
   */
  @Override
  public Object getPrincipal() {
    return this.getEntityId();
  }

  /**
   * Gets the entityID of the requesting entity.
   * 
   * @return the entityID of the requesting entity
   */
  public String getEntityId() {
    return this.authnRequest.get().getIssuer().getValue();
  }

  /**
   * Gets the received {@link AuthnRequest}.
   *
   * @return the {@link AuthnRequest}
   */
  public AuthnRequest getAuthnRequest() {
    return this.authnRequest.get();
  }

  /**
   * Gets the received {@code RelayState} value.
   *
   * @return the RelayState (may be {@code null})
   */
  public String getRelayState() {
    return this.relayState;
  }

  /**
   * Assigns the peer (SP) metadata.
   *
   * @param peerMetadata the peer metadata
   */
  public void setPeerMetadata(final EntityDescriptor peerMetadata) {
    this.peerMetadata = new SerializableOpenSamlObject<>(peerMetadata);
  }

  /**
   * Gets the peer (SP) metadata.
   *
   * @return the peer metadata
   */
  public EntityDescriptor getPeerMetadata() {
    return Optional.ofNullable(this.peerMetadata).map(SerializableOpenSamlObject::get).orElse(null);
  }

  /**
   * Predicate that tells if the peer is a "signature service" peer.
   * 
   * @return {@code true} if the peer is a signature service and {@code false}
   */
  public boolean isSignatureServicePeer() {
    return Optional.ofNullable(this.getPeerMetadata())
        .map(e -> EntityDescriptorUtils.getEntityCategories(e))
        .filter(c -> c.contains(EntityCategoryConstants.SERVICE_TYPE_CATEGORY_SIGSERVICE.getUri()))
        .isPresent();
  }

  /**
   * Gets the binding URI (redirect or POST). Possible values are {@value SAMLConstants#SAML2_REDIRECT_BINDING_URI} and
   * {@value SAMLConstants#SAML2_POST_BINDING_URI}.
   *
   * @return the binding URI used for the {@code AuthnRequest}
   */
  public String getBindingUri() {
    return Optional.ofNullable(this.messageContext.getSubcontext(SAMLBindingContext.class))
        .map(SAMLBindingContext::getBindingUri)
        .orElseThrow(
            () -> new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.INTERNAL, "Invalid message context", this));
  }

  /**
   * Gets the assertion consumer servuce URL to use when posting back an assertion.
   * 
   * @return URL
   */
  public String getAssertionConsumerServiceUrl() {
    return this.assertionConsumerServiceUrl;
  }

  /**
   * Assigns the URL to use when sending back the response.
   *
   * @param assertionConsumerServiceUrl URL
   */
  public void setAssertionConsumerServiceUrl(final String assertionConsumerServiceUrl) {
    this.assertionConsumerServiceUrl =
        Objects.requireNonNull(assertionConsumerServiceUrl, "assertionConsumerServiceUrl must be set");
  }

  /**
   * Gets the {@link NameIDGenerator} to use when generating a {@code NameID} in the assertion that is created based on
   * this request.
   *
   * @return a {@link NameIDGenerator}
   */
  public NameIDGenerator getNameIDGenerator() {
    return this.nameIDGenerator;
  }

  /**
   * Assigns the {@link NameIDGenerator} to use when generating a {@code NameID} in the assertion that is created based
   * on this request.
   *
   * @param nameIDGenerator a {@link NameIDGenerator}
   */
  public void setNameIDGenerator(final NameIDGenerator nameIDGenerator) {
    this.nameIDGenerator = Objects.requireNonNull(nameIDGenerator, "nameIDGenerator must not be null");
  }

  /**
   * Gets a simple log string looking like:
   *
   * <pre>
   * entity-id: 'https://sp.example.com', authn-request: '9873hHYYT'
   * </pre>
   *
   * @return a formatted log string
   */
  public String getLogString() {
    return String.format("entity-id: '%s', authn-request: '%s'",
        Optional.ofNullable(this.getPeerMetadata()).map(EntityDescriptor::getEntityID).orElseGet(() -> "unknown"),
        Optional.ofNullable(this.getAuthnRequest()).map(AuthnRequest::getID).orElseGet(() -> "unknown"));
  }

}
