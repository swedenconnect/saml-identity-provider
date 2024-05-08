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
package se.swedenconnect.spring.saml.idp.metadata;

import jakarta.annotation.Nonnull;
import net.shibboleth.shared.xml.ParserPool;
import net.shibboleth.shared.xml.XMLParserException;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.convert.converter.ConverterRegistry;
import org.springframework.core.io.Resource;
import org.w3c.dom.Element;

import java.io.IOException;
import java.io.InputStream;
import java.util.Optional;

/**
 * A {@link Converter} that gets the property value (e.g., {@code classpath:metadata.xml}) and instantiates an
 * {@link EntityDescriptor} object.
 * <p>
 * To use this converter it has to be instantiated as a bean and then registered in the registry using
 * {@link ConverterRegistry#addConverter(Converter)}.
 * </p>
 * <p>
 * If you are using Spring Boot, do:
 * </p>
 *
 * <pre>
 * &#64;Bean
 * &#64;ConfigurationPropertiesBinding
 * public PropertyToEntityDescriptorConverter propertyToEntityDescriptorConverter() {
 *   return new PropertyToEntityDescriptorConverter();
 * }
 * </pre>
 *
 * @author Martin Lindström
 */
public class PropertyToEntityDescriptorConverter
    implements Converter<String, EntityDescriptor>, ApplicationContextAware {

  /** The application context. */
  private ApplicationContext applicationContext;

  /** {@inheritDoc} */
  @Override
  public void setApplicationContext(@Nonnull final ApplicationContext applicationContext) throws BeansException {
    this.applicationContext = applicationContext;
  }

  /** {@inheritDoc} */
  @Override
  @Nonnull
  public EntityDescriptor convert(@Nonnull final String source) {
    final Resource resource = this.applicationContext.getResource(source);

    try (final InputStream is = resource.getInputStream()) {
      final ParserPool pool = Optional.ofNullable(XMLObjectProviderRegistrySupport.getParserPool())
          .orElseThrow(() -> new IOException("No parser pool available"));
      final Element elm = pool.parse(is).getDocumentElement();
      return (EntityDescriptor) Optional.ofNullable(XMLObjectSupport.getUnmarshaller(elm))
          .orElseThrow(() -> new UnmarshallingException("No unmarshaller for EntityDescriptor"))
          .unmarshall(elm);
    }
    catch (final IOException | UnmarshallingException | XMLParserException e) {
      throw new IllegalArgumentException("Failed to decode EntityDescriptor", e);
    }
  }

}
