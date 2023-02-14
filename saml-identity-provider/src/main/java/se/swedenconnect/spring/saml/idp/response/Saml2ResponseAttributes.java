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

import java.io.Serializable;
import java.util.Optional;

import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;

import se.swedenconnect.spring.saml.idp.utils.Saml2IdentityProviderVersion;
import se.swedenconnect.spring.saml.idp.utils.SerializableOpenSamlObject;

/**
 * Attributes needed when creating a SAML {@link Response} message.
 *
 * @author Martin Lindström
 */
public class Saml2ResponseAttributes implements Serializable {

  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;
  
  /** The RelayState variable. */
  private String relayState;

  /** The {@code InResponseTo} attribute. */
  private String inResponseTo;

  /** The destination attribute. */
  private String destination;

  /** The peer (SP) metadata. */
  private SerializableOpenSamlObject<EntityDescriptor> peerMetadata;

  /**
   * Constructor.
   */
  public Saml2ResponseAttributes() {
  }
  
  /**
   * Gets the {@code RelayState} variable.
   * @return the {@code RelayState} variable
   */
  public String getRelayState() {
    return this.relayState;
  }

  /**
   * Assigns the {@code RelayState} variable.
   * @param relayState the {@code RelayState} variable
   */
  public void setRelayState(final String relayState) {
    this.relayState = relayState;
  }

  /**
   * Gets the {@code InResponseTo} attribute.
   * 
   * @return the {@code InResponseTo} attribute
   */
  public String getInResponseTo() {
    return this.inResponseTo;
  }

  /**
   * Assigns the {@code InResponseTo} attribute.
   * 
   * @param inResponseTo the {@code InResponseTo} attribute
   */
  public void setInResponseTo(final String inResponseTo) {
    this.inResponseTo = inResponseTo;
  }

  /**
   * Gets the {@code Destination} attribute.
   * 
   * @return the {@code Destination} attribute
   */
  public String getDestination() {
    return this.destination;
  }

  /**
   * Gets the {@code Destination} attribute.
   * 
   * @param destination the {@code Destination} attribute
   */
  public void setDestination(final String destination) {
    this.destination = destination;
  }

  /**
   * Gets the peer SAML metadata.
   * 
   * @return the peer SAML metadata
   */
  public EntityDescriptor getPeerMetadata() {
    return Optional.ofNullable(this.peerMetadata).map(SerializableOpenSamlObject::get).orElse(null);
  }

  /**
   * Assigns the peer SAML metadata.
   * 
   * @param peerMetadata the peer SAML metadata
   */
  public void setPeerMetadata(final EntityDescriptor peerMetadata) {
    this.peerMetadata = new SerializableOpenSamlObject<>(peerMetadata, EntityDescriptor.class);
  }

}
