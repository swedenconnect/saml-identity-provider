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
package se.swedenconnect.spring.saml.idp.metadata;

import java.io.IOException;
import java.io.InputStream;

import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;

import net.shibboleth.utilities.java.support.xml.XMLParserException;
import se.swedenconnect.opensaml.saml2.metadata.build.EntityDescriptorBuilder;

/**
 * Provides the Identity Provider metadata that should be published under the IdP metadata publishing endpoint.
 * 
 * @author Martin Lindström
 */
public class Saml2MetadataBuilder extends EntityDescriptorBuilder {

  /**
   * Constructor setting up the builder with no template. This means that the entire {@code EntityDescriptor} object is
   * created from data assigned using the builder.
   */
  public Saml2MetadataBuilder() {
    super();
  }

  /**
   * Constructor setting up the builder with a template {@code EntityDescriptor} that is read from a resource. Users of
   * the bean may now change, add or delete, the elements and attributes of the template object using the assignment
   * methods of the builder.
   * 
   * @param resource the template resource
   * @throws IOException if the resource can not be read
   * @throws UnmarshallingException for unmarshalling errors
   * @throws XMLParserException for XML parsing errors
   */
  public Saml2MetadataBuilder(final InputStream resource)
      throws XMLParserException, UnmarshallingException, IOException {
    super(resource);

    // Remove signature
    this.object().setSignature(null);
  }

  /**
   * Constructor setting up the builder with a template {@code EntityDescriptor}. Users of the bean may now change, add
   * or delete, the elements and attributes of the template object using the assignment methods of the builder.
   * 
   * @param template the template
   * @throws UnmarshallingException for unmarshalling errors
   * @throws MarshallingException for marshalling errors
   */
  public Saml2MetadataBuilder(final EntityDescriptor template) throws UnmarshallingException, MarshallingException {
    super(template);

    // Remove signature
    this.object().setSignature(null);
  }

}
