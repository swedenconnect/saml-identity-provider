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
package se.swedenconnect.spring.saml.idp.client;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Collections;
import java.util.Objects;

import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;

import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import net.shibboleth.utilities.java.support.xml.XMLParserException;

/**
 * An {@link Authentication} object for an authenticated SAML Service Provider.
 *
 * @author Martin Lindström
 */
public class ServiceProviderAuthenticationToken extends AbstractAuthenticationToken {

  private static final long serialVersionUID = 595345017528335123L;

  private final SerializableEntityDescriptor entityDescriptor;

  public ServiceProviderAuthenticationToken(final EntityDescriptor entityDescriptor) {
    super(Collections.emptyList());
    this.entityDescriptor = new SerializableEntityDescriptor(
        Objects.requireNonNull(entityDescriptor, "entityDescriptor must not be null"));
  }

  /**
   * Returns the Service Provider entityID.
   */
  @Override
  public Object getPrincipal() {
    return this.entityDescriptor.getEntityDescriptor().getEntityID();
  }

  /**
   * Returns {@code null}.
   */
  @Override
  public Object getCredentials() {
    return null;
  }

  private static class SerializableEntityDescriptor implements Serializable {

    private static final long serialVersionUID = 4784542622535705443L;

    private EntityDescriptor entityDescriptor;

    SerializableEntityDescriptor(final EntityDescriptor entityDescriptor) {
      this.entityDescriptor = entityDescriptor;
    }

    public EntityDescriptor getEntityDescriptor() {
      return this.entityDescriptor;
    }

    private void writeObject(final ObjectOutputStream out) throws IOException {
      try (ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
        SerializeSupport.writeNode(XMLObjectSupport.marshall(this.entityDescriptor), bos);
        out.writeObject(bos.toByteArray());
      }
      catch (final MarshallingException e) {
        throw new IOException("Failed to marshall EntityDescriptor", e);
      }
    }

    private void readObject(final ObjectInputStream in) throws IOException, ClassNotFoundException {
      final byte[] bytes = (byte[]) in.readObject();
      try (ByteArrayInputStream bis = new ByteArrayInputStream(bytes)) {
        this.entityDescriptor =
            (EntityDescriptor) XMLObjectSupport.unmarshallFromInputStream(XMLObjectProviderRegistrySupport.getParserPool(), bis);
      }
      catch (final UnmarshallingException | XMLParserException e) {
        throw new IOException("Could not unmarshall EntityDescriptor", e);
      }
    }

  }

}
