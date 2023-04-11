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
package se.swedenconnect.spring.saml.idp.attributes;

import java.time.Instant;
import java.time.LocalDate;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.opensaml.core.xml.schema.XSAny;
import org.opensaml.core.xml.schema.XSBase64Binary;
import org.opensaml.core.xml.schema.XSBoolean;
import org.opensaml.core.xml.schema.XSBooleanValue;
import org.opensaml.core.xml.schema.XSDateTime;
import org.opensaml.core.xml.schema.XSInteger;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;

import se.swedenconnect.opensaml.saml2.attribute.AttributeBuilder;
import se.swedenconnect.opensaml.saml2.attribute.AttributeUtils;
import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeConstants;
import se.swedenconnect.spring.saml.idp.OpenSamlTestBase;

/**
 * Test cases for UserAttribute.
 * 
 * @author Martin Lindström
 */
public class UserAttributeTest extends OpenSamlTestBase {

  @Test
  public void testCtor1() {
    final UserAttribute ua = new UserAttribute(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER);
    Assertions.assertEquals(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER, ua.getId());
    Assertions.assertNull(ua.getFriendlyName());
    Assertions.assertEquals(UserAttribute.DEFAULT_NAME_FORMAT, ua.getNameFormat());
    Assertions.assertTrue(ua.getValues().isEmpty());
    Assertions.assertNotNull(ua.toString());

    ua.setFriendlyName(AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_PERSONAL_IDENTITY_NUMBER);
    Assertions.assertEquals(AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_PERSONAL_IDENTITY_NUMBER, ua.getFriendlyName());
  }

  @Test
  public void testCtor2() {
    final UserAttribute ua = new UserAttribute(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER,
        AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_PERSONAL_IDENTITY_NUMBER);
    Assertions.assertEquals(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER, ua.getId());
    Assertions.assertEquals(AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_PERSONAL_IDENTITY_NUMBER, ua.getFriendlyName());
    Assertions.assertEquals(UserAttribute.DEFAULT_NAME_FORMAT, ua.getNameFormat());
    Assertions.assertTrue(ua.getValues().isEmpty());
    Assertions.assertNotNull(ua.toString());
  }

  @Test
  public void testCtor3() {
    final UserAttribute ua = new UserAttribute(AttributeConstants.ATTRIBUTE_NAME_GIVEN_NAME,
        AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_GIVEN_NAME, "Kalle");
    Assertions.assertEquals(AttributeConstants.ATTRIBUTE_NAME_GIVEN_NAME, ua.getId());
    Assertions.assertEquals(AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_GIVEN_NAME, ua.getFriendlyName());
    Assertions.assertEquals(UserAttribute.DEFAULT_NAME_FORMAT, ua.getNameFormat());
    Assertions.assertTrue(ua.getValues().size() == 1);
    Assertions.assertEquals("Kalle", ua.getValues().get(0));
    Assertions.assertNotNull(ua.toString());
  }

  @Test
  public void testCtor4() {
    final UserAttribute ua = new UserAttribute(AttributeConstants.ATTRIBUTE_NAME_GIVEN_NAME,
        AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_GIVEN_NAME, List.of("Kalle", "Kula"));
    Assertions.assertEquals(AttributeConstants.ATTRIBUTE_NAME_GIVEN_NAME, ua.getId());
    Assertions.assertEquals(AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_GIVEN_NAME, ua.getFriendlyName());
    Assertions.assertEquals(UserAttribute.DEFAULT_NAME_FORMAT, ua.getNameFormat());
    Assertions.assertTrue(ua.getValues().size() == 2);
    Assertions.assertEquals("Kalle", ua.getValues().get(0));
    Assertions.assertEquals("Kula", ua.getValues().get(1));
    Assertions.assertNotNull(ua.toString());
  }

  @Test
  public void testSetValue() {
    final UserAttribute ua = new UserAttribute(AttributeConstants.ATTRIBUTE_NAME_GIVEN_NAME,
        AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_GIVEN_NAME);
    ua.setValue("Kalle");
    Assertions.assertEquals(AttributeConstants.ATTRIBUTE_NAME_GIVEN_NAME, ua.getId());
    Assertions.assertEquals(AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_GIVEN_NAME, ua.getFriendlyName());
    Assertions.assertEquals(UserAttribute.DEFAULT_NAME_FORMAT, ua.getNameFormat());
    Assertions.assertTrue(ua.getValues().size() == 1);
    Assertions.assertEquals("Kalle", ua.getValues().get(0));
    Assertions.assertNotNull(ua.toString());
  }

  @Test
  public void testSetValues() {
    final UserAttribute ua = new UserAttribute(AttributeConstants.ATTRIBUTE_NAME_GIVEN_NAME,
        AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_GIVEN_NAME);
    ua.setValues(List.of("Kalle", "Kula"));
    Assertions.assertEquals(AttributeConstants.ATTRIBUTE_NAME_GIVEN_NAME, ua.getId());
    Assertions.assertEquals(AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_GIVEN_NAME, ua.getFriendlyName());
    Assertions.assertEquals(UserAttribute.DEFAULT_NAME_FORMAT, ua.getNameFormat());
    Assertions.assertTrue(ua.getValues().size() == 2);
    Assertions.assertEquals("Kalle", ua.getValues().get(0));
    Assertions.assertEquals("Kula", ua.getValues().get(1));
    Assertions.assertNotNull(ua.toString());
  }

  @Test
  public void testSamlStringAttribute() {
    final Attribute attribute = AttributeBuilder.builder(AttributeConstants.ATTRIBUTE_NAME_GIVEN_NAME)
        .friendlyName(AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_GIVEN_NAME)
        .value("Kalle")
        .build();
    final UserAttribute ua = new UserAttribute(attribute);
    Assertions.assertEquals(AttributeConstants.ATTRIBUTE_NAME_GIVEN_NAME, ua.getId());
    Assertions.assertEquals(AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_GIVEN_NAME, ua.getFriendlyName());
    Assertions.assertEquals(UserAttribute.DEFAULT_NAME_FORMAT, ua.getNameFormat());
    Assertions.assertTrue(ua.getValues().size() == 1);
    Assertions.assertEquals("Kalle", ua.getValues().get(0));
    Assertions.assertNotNull(ua.toString());

    final Attribute a2 = ua.toOpenSamlAttribute();
    Assertions.assertEquals(AttributeConstants.ATTRIBUTE_NAME_GIVEN_NAME, a2.getName());
    Assertions.assertEquals(AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_GIVEN_NAME, a2.getFriendlyName());
    Assertions.assertTrue(a2.getAttributeValues().size() == 1);
    Assertions.assertTrue(a2.getAttributeValues().get(0) instanceof XSString);
    Assertions.assertEquals("Kalle", AttributeUtils.getAttributeStringValue(a2));
  }

  @Test
  public void testNoValues() {
    final UserAttribute ua = new UserAttribute("ID");
    Assertions.assertNotNull(ua.toString());

    final Attribute a = ua.toOpenSamlAttribute();
    Assertions.assertEquals("ID", a.getName());
    Assertions.assertTrue(a.getAttributeValues().isEmpty());

    final UserAttribute ua2 = new UserAttribute("ID");
    ua2.setValues(Collections.emptyList());
    Assertions.assertNotNull(ua.toString());

    final Attribute a2 = ua2.toOpenSamlAttribute();
    Assertions.assertEquals("ID", a2.getName());
    Assertions.assertTrue(a2.getAttributeValues().isEmpty());
  }

  @Test
  public void testSamlBooleanAttribute() {
    final XSBoolean b = AttributeBuilder.createValueObject(XSBoolean.class);
    b.setValue(new XSBooleanValue(Boolean.TRUE, false));

    final Attribute attribute = AttributeBuilder.builder("BooleanAttribute")
        .value(b)
        .build();
    final UserAttribute ua = new UserAttribute(attribute);
    Assertions.assertEquals("BooleanAttribute", ua.getId());
    Assertions.assertEquals(UserAttribute.DEFAULT_NAME_FORMAT, ua.getNameFormat());
    Assertions.assertTrue(ua.getValues().size() == 1);
    Assertions.assertEquals(Boolean.TRUE, ua.getValues().get(0));

    final Attribute a2 = ua.toOpenSamlAttribute();
    Assertions.assertEquals("BooleanAttribute", a2.getName());
    Assertions.assertTrue(a2.getAttributeValues().size() == 1);
    Assertions.assertTrue(a2.getAttributeValues().get(0) instanceof XSBoolean);
    Assertions.assertEquals(Boolean.TRUE, ((XSBoolean) a2.getAttributeValues().get(0)).getValue().getValue());
  }

  @Test
  public void testSamlIntegerAttribute() {
    final XSInteger i = AttributeBuilder.createValueObject(XSInteger.class);
    i.setValue(17);
    
    final XSInteger i2 = AttributeBuilder.createValueObject(XSInteger.class);
    i2.setValue(42);

    final Attribute attribute = AttributeBuilder.builder("IntegerAttribute")
        .value(i)
        .value(i2)
        .build();
    final UserAttribute ua = new UserAttribute(attribute);
    Assertions.assertEquals("IntegerAttribute", ua.getId());
    Assertions.assertEquals(UserAttribute.DEFAULT_NAME_FORMAT, ua.getNameFormat());
    Assertions.assertTrue(ua.getValues().size() == 2);
    Assertions.assertEquals(17, ua.getValues().get(0));
    Assertions.assertEquals(42, ua.getValues().get(1));

    final Attribute a2 = ua.toOpenSamlAttribute();
    Assertions.assertEquals("IntegerAttribute", a2.getName());
    Assertions.assertTrue(a2.getAttributeValues().size() == 2);
    Assertions.assertTrue(a2.getAttributeValues().get(0) instanceof XSInteger);
    Assertions.assertEquals(17, ((XSInteger) a2.getAttributeValues().get(0)).getValue());
    Assertions.assertTrue(a2.getAttributeValues().get(1) instanceof XSInteger);
    Assertions.assertEquals(42, ((XSInteger) a2.getAttributeValues().get(1)).getValue());
  }

  @Test
  public void testSamlDateTimeAttribute() {

    final Instant instant = Instant.now();

    final XSDateTime dt = AttributeBuilder.createValueObject(XSDateTime.class);
    dt.setValue(instant);

    final Attribute attribute = AttributeBuilder.builder("DateTimeAttribute")
        .value(dt)
        .build();
    final UserAttribute ua = new UserAttribute(attribute);
    Assertions.assertEquals("DateTimeAttribute", ua.getId());
    Assertions.assertTrue(ua.getValues().size() == 1);
    Assertions.assertEquals(instant, ua.getValues().get(0));

    final Attribute a2 = ua.toOpenSamlAttribute();
    Assertions.assertEquals("DateTimeAttribute", a2.getName());
    Assertions.assertTrue(a2.getAttributeValues().size() == 1);
    Assertions.assertTrue(a2.getAttributeValues().get(0) instanceof XSDateTime);
    Assertions.assertEquals(instant, ((XSDateTime) a2.getAttributeValues().get(0)).getValue());
  }

  @Test
  public void testSamlXSAnyAttribute() {

    final XSAny any = AttributeBuilder.createValueObject(XSAny.class);
    any.setTextContent("TextValue");

    final Attribute attribute = AttributeBuilder.builder("AnyAttribute")
        .value(any)
        .build();
    final UserAttribute ua = new UserAttribute(attribute);
    Assertions.assertEquals("AnyAttribute", ua.getId());
    Assertions.assertTrue(ua.getValues().size() == 1);
    Assertions.assertEquals("TextValue", ua.getValues().get(0));

    final Attribute a2 = ua.toOpenSamlAttribute();
    Assertions.assertEquals("AnyAttribute", a2.getName());
    Assertions.assertTrue(a2.getAttributeValues().size() == 1);
    Assertions.assertTrue(a2.getAttributeValues().get(0) instanceof XSString);
    Assertions.assertEquals("TextValue", ((XSString) a2.getAttributeValues().get(0)).getValue());
  }

  @Test
  public void testSamlBase64Attribute() {

    final XSBase64Binary b = AttributeBuilder.createValueObject(XSBase64Binary.class);
    b.setValue(Base64.getEncoder().encodeToString("VALUE".getBytes()));

    final Attribute attribute = AttributeBuilder.builder("B64Attribute")
        .value(b)
        .build();
    final UserAttribute ua = new UserAttribute(attribute);
    Assertions.assertEquals("B64Attribute", ua.getId());
    Assertions.assertTrue(ua.getValues().size() == 1);
    Assertions.assertArrayEquals("VALUE".getBytes(), (byte[]) ua.getValues().get(0));

    final Attribute a2 = ua.toOpenSamlAttribute();
    Assertions.assertEquals("B64Attribute", a2.getName());
    Assertions.assertTrue(a2.getAttributeValues().size() == 1);
    Assertions.assertTrue(a2.getAttributeValues().get(0) instanceof XSBase64Binary);
    Assertions.assertEquals(Base64.getEncoder().encodeToString("VALUE".getBytes()),
        ((XSBase64Binary) a2.getAttributeValues().get(0)).getValue());
  }

  @Test
  public void testUnsupportedTypeInAttribute() {

    final EntityDescriptor e = (EntityDescriptor) XMLObjectSupport.buildXMLObject(EntityDescriptor.DEFAULT_ELEMENT_NAME); 

    final Attribute attribute = AttributeBuilder.builder("Attribute")
        .value(e)
        .build();
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      new UserAttribute(attribute);
    });
  }
  
  @Test
  public void testSamlDifferentValueTypes() {
    
    final XSString s = AttributeBuilder.createValueObject(XSString.class);
    s.setValue("Val");
    
    final XSInteger i = AttributeBuilder.createValueObject(XSInteger.class);
    i.setValue(17);

    final Attribute attribute = AttributeBuilder.builder("B64Attribute")
        .value(s)
        .value(i)
        .build();
    
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      new UserAttribute(attribute);
    }); 
  }
  
  @Test
  public void testUnsupportedValueType() {
    
    final UserAttribute ua = new UserAttribute("ID", null, new HashMap<String, String>());
    Assertions.assertThrows(IllegalArgumentException.class, () -> {
      ua.toOpenSamlAttribute();
    });
  }
  
  @Test
  public void testLocalDate() {
    final LocalDate d = LocalDate.parse("1965-04-06");
    final UserAttribute ua = new UserAttribute(AttributeConstants.ATTRIBUTE_NAME_DATE_OF_BIRTH,
        AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_DATE_OF_BIRTH, d);
    
    final Attribute a2 = ua.toOpenSamlAttribute();
    Assertions.assertEquals(AttributeConstants.ATTRIBUTE_NAME_DATE_OF_BIRTH, a2.getName());
    Assertions.assertEquals(AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_DATE_OF_BIRTH, a2.getFriendlyName());
    Assertions.assertTrue(a2.getAttributeValues().size() == 1);
    Assertions.assertTrue(a2.getAttributeValues().get(0) instanceof XSString);
    Assertions.assertEquals("1965-04-06", AttributeUtils.getAttributeStringValue(a2));
    
  }

}
