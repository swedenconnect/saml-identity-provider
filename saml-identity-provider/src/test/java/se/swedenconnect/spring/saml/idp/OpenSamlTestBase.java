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
package se.swedenconnect.spring.saml.idp;

import java.io.InputStream;

import org.junit.jupiter.api.BeforeAll;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.w3c.dom.Element;

import net.shibboleth.shared.xml.XMLParserException;
import se.swedenconnect.opensaml.OpenSAMLInitializer;
import se.swedenconnect.opensaml.OpenSAMLSecurityDefaultsConfig;
import se.swedenconnect.opensaml.OpenSAMLSecurityExtensionConfig;
import se.swedenconnect.opensaml.xmlsec.config.DefaultSecurityConfiguration;

/**
 * Abstract base class that initializes OpenSAML for test classes.
 */
public abstract class OpenSamlTestBase {

  /**
   * Initializes the OpenSAML library.
   *
   * @throws Exception for init errors
   */
  @BeforeAll
  public static void initializeOpenSAML() throws Exception {
    final OpenSAMLInitializer bootstrapper = OpenSAMLInitializer.getInstance();
    if (!bootstrapper.isInitialized()) {
      bootstrapper.initialize(
          new OpenSAMLSecurityDefaultsConfig(new DefaultSecurityConfiguration()),
          new OpenSAMLSecurityExtensionConfig());
    }
  }

  /**
   * Unmarshalls the supplied input stream into the given type.
   *
   * @param inputStream the input stream of the XML resource
   * @param targetClass the required class
   * @param <T> the type
   * @return an {@code XMLObject} of the given type
   * @throws XMLParserException for XML parsing errors
   * @throws UnmarshallingException for unmarshalling errors
   */
  public static <T extends XMLObject> T unmarshall(final InputStream inputStream, final Class<T> targetClass)
      throws XMLParserException, UnmarshallingException {
    final Element elm = XMLObjectProviderRegistrySupport.getParserPool().parse(inputStream).getDocumentElement();
    return targetClass.cast(XMLObjectSupport.getUnmarshaller(elm).unmarshall(elm));
  }

  /**
   * Marshalls the supplied XML object into a DOM {@link Element}.
   *
   * @param <T> the type
   * @param object the object to marahll
   * @return a DOM {@link Element}
   * @throws MarshallingException for marshalling errors
   */
  public static <T extends XMLObject> Element marshall(final T object) throws MarshallingException {
    return XMLObjectSupport.marshall(object);
  }

}
