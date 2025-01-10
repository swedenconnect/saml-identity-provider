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
package se.swedenconnect.spring.saml.idp.attributes;

import net.shibboleth.shared.xml.SerializeSupport;
import net.shibboleth.shared.xml.XMLParserException;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.schema.XSAny;
import org.opensaml.core.xml.schema.XSBase64Binary;
import org.opensaml.core.xml.schema.XSBoolean;
import org.opensaml.core.xml.schema.XSBooleanValue;
import org.opensaml.core.xml.schema.XSDateTime;
import org.opensaml.core.xml.schema.XSInteger;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.Attribute;
import org.springframework.util.Assert;
import org.w3c.dom.Element;
import se.swedenconnect.opensaml.saml2.attribute.AttributeBuilder;
import se.swedenconnect.opensaml.saml2.attribute.AttributeUtils;
import se.swedenconnect.spring.saml.idp.Saml2IdentityProviderVersion;
import se.swedenconnect.spring.saml.idp.attributes.eidas.EidasAttributeValue;
import se.swedenconnect.spring.saml.idp.attributes.eidas.EidasAttributeValueConverter;

import java.io.ByteArrayInputStream;
import java.io.Serial;
import java.io.Serializable;
import java.time.Instant;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * A representation of a user (identity) attribute.
 *
 * @author Martin Lindström
 */
public class UserAttribute implements Serializable {

  /** The default name format for SAML attributes. */
  public static final String DEFAULT_NAME_FORMAT = Attribute.URI_REFERENCE;

  /** For serializing. */
  @Serial
  private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

  /** The date time formatter to use. */
  private static final DateTimeFormatter formatter = DateTimeFormatter.ISO_LOCAL_DATE;

  /** The attribute ID (name). */
  private final String id;

  /** The attribute friendly name. */
  private String friendlyName;

  /** The attribute name format. */
  private String nameFormat;

  /** The attribute value(s). */
  private List<? extends Serializable> values;

  /**
   * Constructor.
   *
   * @param id the attribute ID (name)
   */
  public UserAttribute(final String id) {
    this(id, null, (Serializable) null);
  }

  /**
   * Constructor.
   *
   * @param id the attribute ID (name)
   * @param friendlyName the attribute friendly name
   */
  public UserAttribute(final String id, final String friendlyName) {
    this(id, friendlyName, (Serializable) null);
  }

  /**
   * Constructor.
   *
   * @param id the attribute ID (name)
   * @param friendlyName the attribute friendly name
   * @param value the attribute value
   */
  public UserAttribute(final String id, final String friendlyName, final Serializable value) {
    this(id, friendlyName, Optional.ofNullable(value).map(List::of).orElse(null));
  }

  /**
   * Constructor.
   *
   * @param id the attribute ID (name)
   * @param friendlyName the attribute friendly name
   * @param values the attribute values
   */
  public UserAttribute(final String id, final String friendlyName, final List<? extends Serializable> values) {
    this.id = Objects.requireNonNull(id, "id must not be null");
    this.friendlyName = friendlyName;
    this.values = values;
  }

  /**
   * Constructs an {@code UserAttribute} given an OpenSAML {@link Attribute}.
   *
   * @param attribute an OpenSAML {@link Attribute}
   */
  public UserAttribute(final Attribute attribute) {
    Assert.notNull(attribute, "attribute must not be null");
    this.id = Objects.requireNonNull(attribute.getName(), "attribute.name must not be null");
    this.friendlyName = attribute.getFriendlyName();
    this.nameFormat = attribute.getNameFormat();
    if (!attribute.getAttributeValues().isEmpty()) {

      // Assert that all values have the same type and return this type.
      final Class<?> valueType = processValueType(attribute.getAttributeValues());

      if (EidasAttributeValueConverter.isEidasAttribute(valueType)) {
        this.values = EidasAttributeValueConverter.getValues(attribute, valueType);
      }
      else if (XSString.class.isAssignableFrom(valueType) || XSAny.class.isAssignableFrom(valueType)) {
        this.values = AttributeUtils.getAttributeValues(attribute, XSString.class).stream()
            .map(XSString::getValue)
            .collect(Collectors.toList());
      }
      else if (XSBoolean.class.isAssignableFrom(valueType)) {
        this.values = AttributeUtils.getAttributeValues(attribute, XSBoolean.class).stream()
            .map(XSBoolean::getValue)
            .filter(Objects::nonNull)
            .map(XSBooleanValue::getValue)
            .collect(Collectors.toList());
      }
      else if (XSInteger.class.isAssignableFrom(valueType)) {
        this.values = AttributeUtils.getAttributeValues(attribute, XSInteger.class).stream()
            .map(XSInteger::getValue)
            .collect(Collectors.toList());
      }
      else if (XSDateTime.class.isAssignableFrom(valueType)) {
        this.values = AttributeUtils.getAttributeValues(attribute, XSDateTime.class).stream()
            .map(XSDateTime::getValue)
            .collect(Collectors.toList());
      }
      else if (XSBase64Binary.class.isAssignableFrom(valueType)) {
        this.values = AttributeUtils.getAttributeValues(attribute, XSBase64Binary.class).stream()
            .map(XSBase64Binary::getValue)
            .map(e -> Base64.getDecoder().decode(e))
            .collect(Collectors.toList());
      }
      else {
        this.values = attribute.getAttributeValues().stream()
            .map(UnknownAttributeValue::new)
            .collect(Collectors.toList());

      }
    }
  }

  /**
   * Gets the attribute ID (name).
   *
   * @return the attribute ID (name)
   */
  public String getId() {
    return this.id;
  }

  /**
   * Gets the attribute friendly name.
   *
   * @return the attribute friendly name (or {@code null} if none has been assigned)
   */
  public String getFriendlyName() {
    return this.friendlyName;
  }

  /**
   * Assigns the friendly name.
   *
   * @param friendlyName the friendly name
   */
  public void setFriendlyName(final String friendlyName) {
    this.friendlyName = friendlyName;
  }

  /**
   * Gets the name format URI for the attribute.
   *
   * @return the name format
   */
  public String getNameFormat() {
    return Optional.ofNullable(this.nameFormat).orElse(DEFAULT_NAME_FORMAT);
  }

  /**
   * Assigns the attribute name format.
   *
   * @param nameFormat the name format
   */
  public void setNameFormat(final String nameFormat) {
    this.nameFormat = nameFormat;
  }

  /**
   * Gets the attribute value(s).
   *
   * @return the attribute value(s)
   */
  public List<? extends Serializable> getValues() {
    return Optional.ofNullable(this.values).orElse(Collections.emptyList());
  }

  /**
   * Gets the attribute value(s) in string format.
   *
   * @return the attribute value(s) in string format
   */
  public List<String> getStringValues() {
    return this.getValues().stream()
        .filter(Objects::nonNull)
        .map(UserAttribute::toStringValue)
        .toList();
  }

  /**
   * Assigns the attribute value.
   *
   * @param value the value
   * @see #setValues(List)
   */
  public void setValue(final Serializable value) {
    this.values = List.of(value);
  }

  /**
   * Assigns the attribute values.
   *
   * @param values the values
   * @see #setValue(Serializable)
   */
  public void setValues(final List<? extends Serializable> values) {
    this.values = values;
  }

  /**
   * Converts an attribute value to a {@link String}.
   *
   * @param value the value to convert
   * @return a {@link String}
   */
  private static String toStringValue(final Serializable value) {
    if (value instanceof String) {
      return (String) value;
    }
    else if (value instanceof Integer) {
      return ((Integer) value).toString();
    }
    else if (value instanceof Boolean) {
      return ((Boolean) value).toString();
    }
    else if (value instanceof LocalDate) {
      return formatter.format((LocalDate) value);
    }
    else if (value instanceof Instant) {
      return ((Instant) value).toString();
    }
    else if (value instanceof byte[]) {
      return Base64.getEncoder().encodeToString((byte[]) value);
    }
    else if (value instanceof EidasAttributeValue) {
      return ((EidasAttributeValue<?>) value).getValueAsString();
    }
    else {
      return value.toString();
    }
  }

  /**
   * Converts this object into an OpenSAML {@link Attribute} object.
   *
   * @return an OpenSAML {@link Attribute}
   */
  public Attribute toOpenSamlAttribute() {
    final AttributeBuilder builder = AttributeBuilder.builder(this.getId())
        .friendlyName(this.getFriendlyName())
        .nameFormat(this.getNameFormat());

    if (this.values != null) {
      for (final Object v : this.values) {
        if (v instanceof String) {
          builder.value((String) v);
        }
        else if (v instanceof Integer) {
          final XSInteger o = AttributeBuilder.createValueObject(XSInteger.TYPE_NAME, XSInteger.class);
          o.setValue((Integer) v);
          builder.value(o);
        }
        else if (v instanceof Boolean) {
          final XSBoolean o = AttributeBuilder.createValueObject(XSBoolean.TYPE_NAME, XSBoolean.class);
          o.setValue(new XSBooleanValue((Boolean) v, false));
          builder.value(o);
        }
        else if (v instanceof LocalDate) {
          // OpenSAML doesn't support xs:date, so I guess it is seldom used. Let's put it in a
          // string value ...
          builder.value(formatter.format((LocalDate) v));
        }
        else if (v instanceof Instant) {
          final XSDateTime o = AttributeBuilder.createValueObject(XSDateTime.TYPE_NAME, XSDateTime.class);
          o.setValue((Instant) v);
          builder.value(o);
        }
        else if (v instanceof byte[]) {
          final XSBase64Binary o = AttributeBuilder.createValueObject(XSBase64Binary.TYPE_NAME, XSBase64Binary.class);
          o.setValue(Base64.getEncoder().encodeToString((byte[]) v));
          builder.value(o);
        }
        else if (v instanceof EidasAttributeValue) {
          final XMLObject o = ((EidasAttributeValue<?>) v).createXmlObject();
          builder.value(o);
        }
        else if (v instanceof UnknownAttributeValue) {
          final XMLObject o = ((UnknownAttributeValue) v).createXmlObject();
          builder.value(o);
        }
        else {
          throw new IllegalArgumentException("Unsupported attribute value - " + v.getClass().getSimpleName());
        }
      }
    }

    return builder.build();
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    final StringBuilder sb = new StringBuilder();
    sb.append(this.id);
    if (this.friendlyName != null) {
      sb.append(", (").append(this.friendlyName).append(")");
    }
    final List<? extends Serializable> v = this.getValues();
    if (!v.isEmpty()) {
      if (v.size() == 1) {
        sb.append(", value=").append(v.get(0));
      }
      else {
        sb.append(", values=").append(this.valuesToString());
      }
    }
    return sb.toString();
  }

  public String valuesToString() {
    final StringBuilder sb = new StringBuilder();
    final List<? extends Serializable> values = this.getValues();
    if (values.isEmpty()) {
      return null;
    }
    sb.append(values.get(0));
    if (values.size() > 1) {
      for (int i = 1; i < values.size(); i++) {
        sb.append(",").append(values.get(i));
      }
    }
    return sb.toString();
  }

  /**
   * Checks that an attribute's values all are of the same type
   *
   * @param values the values to check
   * @return the value type
   * @throws IllegalArgumentException if different types appear
   */
  private static Class<?> processValueType(final List<XMLObject> values) throws IllegalArgumentException {
    final Iterator<XMLObject> i = values.iterator();
    final Class<?> type = i.next().getClass();
    while (i.hasNext()) {
      if (!type.isInstance(i.next())) {
        throw new IllegalArgumentException(
            "Multi-valued SAML attribute has different value types - this is not supported");
      }
    }
    return type;
  }

  /**
   * Class used to store attribute value types that we don't know how to parse.
   */
  public static class UnknownAttributeValue implements Serializable {

    @Serial
    private static final long serialVersionUID = Saml2IdentityProviderVersion.SERIAL_VERSION_UID;

    /** The encoding of the value object. */
    private final String encoding;

    /**
     * Constructor.
     *
     * @param value the XML value
     */
    public UnknownAttributeValue(final XMLObject value) {
      try {
        final Element element = XMLObjectSupport.marshall(Objects.requireNonNull(value, "value must not be null"));
        this.encoding = SerializeSupport.nodeToString(element);
      }
      catch (final MarshallingException e) {
        throw new IllegalArgumentException("Failed to marshall " + value.getElementQName(), e);
      }
    }

    /**
     * Creates the {@link XMLObject} given its encoding.
     *
     * @return an {@link XMLObject}
     */
    public XMLObject createXmlObject() {
      try {
        return XMLObjectSupport.unmarshallFromInputStream(
            Objects.requireNonNull(XMLObjectProviderRegistrySupport.getParserPool()),
            new ByteArrayInputStream(this.encoding.getBytes()));
      }
      catch (final XMLParserException | UnmarshallingException e) {
        throw new SecurityException(e);
      }
    }

    /** {@inheritDoc} */
    @Override
    public String toString() {
      return this.encoding;
    }

  }

}
