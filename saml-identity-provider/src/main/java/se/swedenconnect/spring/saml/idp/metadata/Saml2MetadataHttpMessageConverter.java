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
package se.swedenconnect.spring.saml.idp.metadata;

import net.shibboleth.shared.xml.ParserPool;
import net.shibboleth.shared.xml.SerializeSupport;
import net.shibboleth.shared.xml.XMLParserException;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.AbstractHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.lang.NonNull;
import org.w3c.dom.Element;

import java.io.IOException;
import java.util.Optional;

/**
 * A {@link HttpMessageConverter} that reads and writes {@link EntityDescriptor} objects.
 *
 * @author Martin Lindström
 */
public class Saml2MetadataHttpMessageConverter extends AbstractHttpMessageConverter<EntityDescriptor> {

  /**
   * Constructor.
   */
  public Saml2MetadataHttpMessageConverter() {
    super(MediaType.APPLICATION_XML, new MediaType("application", "samlmetadata+xml"));
  }

  /** {@inheritDoc} */
  @Override
  protected boolean supports(@NonNull final Class<?> clazz) {
    return EntityDescriptor.class.isAssignableFrom(clazz);
  }

  /** {@inheritDoc} */
  @Override
  @NonNull
  protected EntityDescriptor readInternal(@NonNull final Class<? extends EntityDescriptor> clazz,
      final HttpInputMessage inputMessage) throws IOException, HttpMessageNotReadableException {

    try {
      final ParserPool pool = XMLObjectProviderRegistrySupport.getParserPool();
      final Element elm = Optional.ofNullable(pool)
          .orElseThrow(() -> new XMLParserException("No parser pool"))
          .parse(inputMessage.getBody()).getDocumentElement();

      return (EntityDescriptor) Optional.ofNullable(XMLObjectSupport.getUnmarshaller(elm))
          .orElseThrow(() -> new UnmarshallingException("No unmarshaller found for EntityDescriptor"))
          .unmarshall(elm);
    }
    catch (final UnmarshallingException | XMLParserException e) {
      throw new HttpMessageNotReadableException("Failed to unmarshall input to EntityDescriptor", e, inputMessage);
    }
  }

  /** {@inheritDoc} */
  @Override
  protected void writeInternal(@NonNull final EntityDescriptor t, final HttpOutputMessage outputMessage)
      throws IOException, HttpMessageNotWritableException {
    try {
      SerializeSupport.writeNode(XMLObjectSupport.marshall(t), outputMessage.getBody());
    }
    catch (final MarshallingException e) {
      throw new HttpMessageNotWritableException("Failed to marshall EntityDescriptor", e);
    }

  }

}
