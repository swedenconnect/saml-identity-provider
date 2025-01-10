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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
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
import se.swedenconnect.opensaml.eidas.ext.attributes.BirthNameType;
import se.swedenconnect.opensaml.eidas.ext.attributes.CountryOfBirthType;
import se.swedenconnect.opensaml.eidas.ext.attributes.CountryOfResidenceType;
import se.swedenconnect.opensaml.eidas.ext.attributes.CurrentAddressStructuredType;
import se.swedenconnect.opensaml.eidas.ext.attributes.CurrentAddressType;
import se.swedenconnect.opensaml.eidas.ext.attributes.CurrentFamilyNameType;
import se.swedenconnect.opensaml.eidas.ext.attributes.CurrentGivenNameType;
import se.swedenconnect.opensaml.eidas.ext.attributes.DateOfBirthType;
import se.swedenconnect.opensaml.eidas.ext.attributes.GenderType;
import se.swedenconnect.opensaml.eidas.ext.attributes.GenderTypeEnumeration;
import se.swedenconnect.opensaml.eidas.ext.attributes.NationalityType;
import se.swedenconnect.opensaml.eidas.ext.attributes.PersonIdentifierType;
import se.swedenconnect.opensaml.eidas.ext.attributes.PlaceOfBirthType;
import se.swedenconnect.opensaml.saml2.attribute.AttributeBuilder;
import se.swedenconnect.opensaml.saml2.attribute.AttributeUtils;
import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeConstants;
import se.swedenconnect.spring.saml.idp.OpenSamlTestBase;
import se.swedenconnect.spring.saml.idp.attributes.eidas.CountryString;
import se.swedenconnect.spring.saml.idp.attributes.eidas.CurrentAddress;
import se.swedenconnect.spring.saml.idp.attributes.eidas.DateOfBirth;
import se.swedenconnect.spring.saml.idp.attributes.eidas.Gender;
import se.swedenconnect.spring.saml.idp.attributes.eidas.PersonIdentifier;
import se.swedenconnect.spring.saml.idp.attributes.eidas.PlaceOfBirth;
import se.swedenconnect.spring.saml.idp.attributes.eidas.TransliterationString;

import java.time.Instant;
import java.time.LocalDate;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

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
    Assertions.assertEquals("Kalle", ua.getStringValues().get(0));
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
    Assertions.assertEquals("true", ua.getStringValues().get(0));

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
    Assertions.assertEquals("17", ua.getStringValues().get(0));
    Assertions.assertEquals("42", ua.getStringValues().get(1));

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
    final String instantString = instant.toString();

    final XSDateTime dt = AttributeBuilder.createValueObject(XSDateTime.class);
    dt.setValue(instant);

    final Attribute attribute = AttributeBuilder.builder("DateTimeAttribute")
        .value(dt)
        .build();
    final UserAttribute ua = new UserAttribute(attribute);
    Assertions.assertEquals("DateTimeAttribute", ua.getId());
    Assertions.assertTrue(ua.getValues().size() == 1);
    Assertions.assertEquals(instant, ua.getValues().get(0));
    Assertions.assertEquals(instantString, ua.getStringValues().get(0));

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
    Assertions.assertEquals("TextValue", ua.getStringValues().get(0));

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
    Assertions.assertEquals(Base64.getEncoder().encodeToString("VALUE".getBytes()), ua.getStringValues().get(0));

    final Attribute a2 = ua.toOpenSamlAttribute();
    Assertions.assertEquals("B64Attribute", a2.getName());
    Assertions.assertTrue(a2.getAttributeValues().size() == 1);
    Assertions.assertTrue(a2.getAttributeValues().get(0) instanceof XSBase64Binary);
    Assertions.assertEquals(Base64.getEncoder().encodeToString("VALUE".getBytes()),
        ((XSBase64Binary) a2.getAttributeValues().get(0)).getValue());
  }

  @Test
  public void testUnsupportedTypeInAttribute() {

    final EntityDescriptor e =
        (EntityDescriptor) XMLObjectSupport.buildXMLObject(EntityDescriptor.DEFAULT_ELEMENT_NAME);
    e.setID("Hello");

    final Attribute attribute = AttributeBuilder.builder("Attribute")
        .value(e)
        .build();

    final UserAttribute ua = new UserAttribute(attribute);

    final Attribute attribute2 = ua.toOpenSamlAttribute();
    Assertions.assertEquals("Attribute", attribute2.getName());
    Assertions.assertEquals(1, attribute2.getAttributeValues().size());
    Assertions.assertTrue(attribute2.getAttributeValues().get(0) instanceof EntityDescriptor);
    Assertions.assertEquals("Hello",
        ((EntityDescriptor) attribute2.getAttributeValues().get(0)).getID());

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

    Assertions.assertThrows(IllegalArgumentException.class, () -> new UserAttribute(attribute));
  }

  @Test
  public void testUnsupportedValueType() {

    final UserAttribute ua = new UserAttribute("ID", null, new HashMap<String, String>());
    Assertions.assertThrows(IllegalArgumentException.class, ua::toOpenSamlAttribute);
  }

  @Test
  public void testLocalDate() {
    final LocalDate d = LocalDate.parse("1965-04-06");
    final UserAttribute ua = new UserAttribute(AttributeConstants.ATTRIBUTE_NAME_DATE_OF_BIRTH,
        AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_DATE_OF_BIRTH, d);

    Assertions.assertEquals("1965-04-06", ua.getStringValues().get(0));

    final Attribute a2 = ua.toOpenSamlAttribute();
    Assertions.assertEquals(AttributeConstants.ATTRIBUTE_NAME_DATE_OF_BIRTH, a2.getName());
    Assertions.assertEquals(AttributeConstants.ATTRIBUTE_FRIENDLY_NAME_DATE_OF_BIRTH, a2.getFriendlyName());
    Assertions.assertTrue(a2.getAttributeValues().size() == 1);
    Assertions.assertTrue(a2.getAttributeValues().get(0) instanceof XSString);
    Assertions.assertEquals("1965-04-06", AttributeUtils.getAttributeStringValue(a2));

  }

  @Test
  public void testEidasPersonIdentifier() {
    final PersonIdentifierType pi =
        AttributeBuilder.createValueObject(PersonIdentifierType.TYPE_NAME, PersonIdentifierType.class);
    pi.setValue("ES/AT/02635542Y");

    final Attribute attribute = AttributeBuilder.builder(
            se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_PERSON_IDENTIFIER_ATTRIBUTE_NAME)
        .friendlyName(
            se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_PERSON_IDENTIFIER_ATTRIBUTE_FRIENDLY_NAME)
        .value(pi)
        .build();

    final UserAttribute ua = new UserAttribute(attribute);

    Assertions.assertEquals(
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_PERSON_IDENTIFIER_ATTRIBUTE_NAME,
        ua.getId());
    Assertions.assertEquals(
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_PERSON_IDENTIFIER_ATTRIBUTE_FRIENDLY_NAME,
        ua.getFriendlyName());

    Assertions.assertTrue(ua.getValues().get(0) instanceof PersonIdentifier);
    Assertions.assertEquals("ES/AT/02635542Y", ua.getValues().get(0).toString());
    Assertions.assertEquals("ES/AT/02635542Y", ua.getStringValues().get(0));

    final Attribute attribute2 = ua.toOpenSamlAttribute();
    Assertions.assertEquals(
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_PERSON_IDENTIFIER_ATTRIBUTE_NAME,
        attribute2.getName());
    Assertions.assertTrue(attribute2.getAttributeValues().size() == 1);
    Assertions.assertTrue(attribute2.getAttributeValues().get(0) instanceof PersonIdentifierType);
    Assertions.assertEquals("ES/AT/02635542Y",
        ((PersonIdentifierType) attribute2.getAttributeValues().get(0)).getValue());
  }

  @Test
  public void testEidasBirthName() {
    final BirthNameType value = AttributeBuilder.createValueObject(BirthNameType.TYPE_NAME, BirthNameType.class);
    value.setValue("Jackie Onassis");
    value.setLatinScript(true);

    final BirthNameType value2 = AttributeBuilder.createValueObject(BirthNameType.TYPE_NAME, BirthNameType.class);
    value2.setValue("Jαξκιε Ονασσισ");
    value2.setLatinScript(false);

    final Attribute attribute = AttributeBuilder.builder(
            se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_BIRTH_NAME_ATTRIBUTE_NAME)
        .friendlyName(
            se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_BIRTH_NAME_ATTRIBUTE_FRIENDLY_NAME)
        .value(value)
        .value(value2)
        .build();

    final UserAttribute ua = new UserAttribute(attribute);

    Assertions.assertEquals(
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_BIRTH_NAME_ATTRIBUTE_NAME,
        ua.getId());
    Assertions.assertEquals(
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_BIRTH_NAME_ATTRIBUTE_FRIENDLY_NAME,
        ua.getFriendlyName());

    Assertions.assertEquals(2, ua.getValues().size());
    Assertions.assertTrue(ua.getValues().get(0) instanceof TransliterationString);
    Assertions.assertEquals("Jackie Onassis", ua.getValues().get(0).toString());
    Assertions.assertTrue(ua.getValues().get(1) instanceof TransliterationString);
    Assertions.assertEquals("Jαξκιε Ονασσισ", ua.getValues().get(1).toString());

    final Attribute attribute2 = ua.toOpenSamlAttribute();
    Assertions.assertEquals(
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_BIRTH_NAME_ATTRIBUTE_NAME,
        attribute2.getName());
    Assertions.assertTrue(attribute2.getAttributeValues().size() == 2);
    Assertions.assertTrue(attribute2.getAttributeValues().get(0) instanceof BirthNameType);
    Assertions.assertEquals("Jackie Onassis",
        ((BirthNameType) attribute2.getAttributeValues().get(0)).getValue());
    Assertions.assertTrue(((BirthNameType) attribute2.getAttributeValues().get(0)).getLatinScript());

    Assertions.assertTrue(attribute2.getAttributeValues().get(1) instanceof BirthNameType);
    Assertions.assertEquals("Jαξκιε Ονασσισ",
        ((BirthNameType) attribute2.getAttributeValues().get(1)).getValue());
    Assertions.assertFalse(((BirthNameType) attribute2.getAttributeValues().get(1)).getLatinScript());
  }

  @Test
  public void testEidasCurrentFamilyName() {
    final CurrentFamilyNameType value =
        AttributeBuilder.createValueObject(CurrentFamilyNameType.TYPE_NAME, CurrentFamilyNameType.class);
    value.setValue("Onassis");
    value.setLatinScript(true);

    final CurrentFamilyNameType value2 =
        AttributeBuilder.createValueObject(CurrentFamilyNameType.TYPE_NAME, CurrentFamilyNameType.class);
    value2.setValue("Ονασσισ");
    value2.setLatinScript(false);

    final Attribute attribute = AttributeBuilder.builder(
            se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_CURRENT_FAMILY_NAME_ATTRIBUTE_NAME)
        .friendlyName(
            se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_CURRENT_FAMILY_NAME_ATTRIBUTE_FRIENDLY_NAME)
        .value(value)
        .value(value2)
        .build();

    final UserAttribute ua = new UserAttribute(attribute);

    Assertions.assertEquals(
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_CURRENT_FAMILY_NAME_ATTRIBUTE_NAME,
        ua.getId());
    Assertions.assertEquals(
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_CURRENT_FAMILY_NAME_ATTRIBUTE_FRIENDLY_NAME,
        ua.getFriendlyName());

    Assertions.assertEquals(2, ua.getValues().size());
    Assertions.assertTrue(ua.getValues().get(0) instanceof TransliterationString);
    Assertions.assertEquals("Onassis", ua.getValues().get(0).toString());
    Assertions.assertTrue(ua.getValues().get(1) instanceof TransliterationString);
    Assertions.assertEquals("Ονασσισ", ua.getValues().get(1).toString());

    final Attribute attribute2 = ua.toOpenSamlAttribute();
    Assertions.assertEquals(
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_CURRENT_FAMILY_NAME_ATTRIBUTE_NAME,
        attribute2.getName());
    Assertions.assertTrue(attribute2.getAttributeValues().size() == 2);
    Assertions.assertTrue(attribute2.getAttributeValues().get(0) instanceof CurrentFamilyNameType);
    Assertions.assertEquals("Onassis",
        ((CurrentFamilyNameType) attribute2.getAttributeValues().get(0)).getValue());
    Assertions.assertTrue(((CurrentFamilyNameType) attribute2.getAttributeValues().get(0)).getLatinScript());

    Assertions.assertTrue(attribute2.getAttributeValues().get(1) instanceof CurrentFamilyNameType);
    Assertions.assertEquals("Ονασσισ",
        ((CurrentFamilyNameType) attribute2.getAttributeValues().get(1)).getValue());
    Assertions.assertFalse(((CurrentFamilyNameType) attribute2.getAttributeValues().get(1)).getLatinScript());
  }

  @Test
  public void testEidasCurrentGivenName() {
    final CurrentGivenNameType value =
        AttributeBuilder.createValueObject(CurrentGivenNameType.TYPE_NAME, CurrentGivenNameType.class);
    value.setValue("Jackie");

    final Attribute attribute = AttributeBuilder.builder(
            se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_CURRENT_GIVEN_NAME_ATTRIBUTE_NAME)
        .friendlyName(
            se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_CURRENT_GIVEN_NAME_ATTRIBUTE_FRIENDLY_NAME)
        .value(value)
        .build();

    final UserAttribute ua = new UserAttribute(attribute);

    Assertions.assertEquals(
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_CURRENT_GIVEN_NAME_ATTRIBUTE_NAME,
        ua.getId());
    Assertions.assertEquals(
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_CURRENT_GIVEN_NAME_ATTRIBUTE_FRIENDLY_NAME,
        ua.getFriendlyName());

    Assertions.assertEquals(1, ua.getValues().size());
    Assertions.assertTrue(ua.getValues().get(0) instanceof TransliterationString);
    Assertions.assertEquals("Jackie", ua.getValues().get(0).toString());

    final Attribute attribute2 = ua.toOpenSamlAttribute();
    Assertions.assertEquals(
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_CURRENT_GIVEN_NAME_ATTRIBUTE_NAME,
        attribute2.getName());
    Assertions.assertTrue(attribute2.getAttributeValues().size() == 1);
    Assertions.assertTrue(attribute2.getAttributeValues().get(0) instanceof CurrentGivenNameType);
    Assertions.assertEquals("Jackie",
        ((CurrentGivenNameType) attribute2.getAttributeValues().get(0)).getValue());
    Assertions.assertTrue(((CurrentGivenNameType) attribute2.getAttributeValues().get(0)).getLatinScript());
    Assertions
        .assertNull(((CurrentGivenNameType) attribute2.getAttributeValues().get(0)).getLatinScriptXSBooleanValue());
  }

  @Test
  public void testEidasDateOfBirth() {

    final LocalDate date = LocalDate.parse("1929-07-28");

    final DateOfBirthType dob = AttributeBuilder.createValueObject(DateOfBirthType.TYPE_NAME, DateOfBirthType.class);
    dob.setDate(date);

    final Attribute attribute = AttributeBuilder.builder(
            se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_DATE_OF_BIRTH_ATTRIBUTE_NAME)
        .friendlyName(
            se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_DATE_OF_BIRTH_ATTRIBUTE_FRIENDLY_NAME)
        .value(dob)
        .build();

    final UserAttribute ua = new UserAttribute(attribute);

    Assertions.assertEquals(
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_DATE_OF_BIRTH_ATTRIBUTE_NAME,
        ua.getId());
    Assertions.assertEquals(
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_DATE_OF_BIRTH_ATTRIBUTE_FRIENDLY_NAME,
        ua.getFriendlyName());

    Assertions.assertTrue(ua.getValues().get(0) instanceof DateOfBirth);
    Assertions.assertEquals(date.toString(), ua.getValues().get(0).toString());

    final Attribute attribute2 = ua.toOpenSamlAttribute();
    Assertions.assertEquals(
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_DATE_OF_BIRTH_ATTRIBUTE_NAME,
        attribute2.getName());
    Assertions.assertTrue(attribute2.getAttributeValues().size() == 1);
    Assertions.assertTrue(attribute2.getAttributeValues().get(0) instanceof DateOfBirthType);
    Assertions.assertEquals(date,
        ((DateOfBirthType) attribute2.getAttributeValues().get(0)).getDate());
  }

  @Test
  public void testEidasGender() {
    final GenderType gender = AttributeBuilder.createValueObject(GenderType.TYPE_NAME, GenderType.class);
    gender.setGender(GenderTypeEnumeration.MALE);

    final Attribute attribute = AttributeBuilder.builder(
            se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_GENDER_ATTRIBUTE_NAME)
        .friendlyName(
            se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_GENDER_ATTRIBUTE_FRIENDLY_NAME)
        .value(gender)
        .build();

    final UserAttribute ua = new UserAttribute(attribute);

    Assertions.assertEquals(
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_GENDER_ATTRIBUTE_NAME,
        ua.getId());
    Assertions.assertEquals(
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_GENDER_ATTRIBUTE_FRIENDLY_NAME,
        ua.getFriendlyName());

    Assertions.assertTrue(ua.getValues().get(0) instanceof Gender);
    Assertions.assertEquals("Male", ua.getValues().get(0).toString());

    final Attribute attribute2 = ua.toOpenSamlAttribute();
    Assertions.assertEquals(
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_GENDER_ATTRIBUTE_NAME,
        attribute2.getName());
    Assertions.assertTrue(attribute2.getAttributeValues().size() == 1);
    Assertions.assertTrue(attribute2.getAttributeValues().get(0) instanceof GenderType);
    Assertions.assertEquals(GenderTypeEnumeration.MALE,
        ((GenderType) attribute2.getAttributeValues().get(0)).getGender());
  }

  @Test
  public void testEidasPlaceOfBirth() {
    final PlaceOfBirthType pob = AttributeBuilder.createValueObject(PlaceOfBirthType.TYPE_NAME, PlaceOfBirthType.class);
    pob.setValue("Stockholm");

    final Attribute attribute = AttributeBuilder.builder(
            se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_PLACE_OF_BIRTH_ATTRIBUTE_NAME)
        .friendlyName(
            se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_PLACE_OF_BIRTH_ATTRIBUTE_FRIENDLY_NAME)
        .value(pob)
        .build();

    final UserAttribute ua = new UserAttribute(attribute);

    Assertions.assertEquals(
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_PLACE_OF_BIRTH_ATTRIBUTE_NAME,
        ua.getId());
    Assertions.assertEquals(
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_PLACE_OF_BIRTH_ATTRIBUTE_FRIENDLY_NAME,
        ua.getFriendlyName());

    Assertions.assertTrue(ua.getValues().get(0) instanceof PlaceOfBirth);
    Assertions.assertEquals("Stockholm", ua.getValues().get(0).toString());

    final Attribute attribute2 = ua.toOpenSamlAttribute();
    Assertions.assertEquals(
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_PLACE_OF_BIRTH_ATTRIBUTE_NAME,
        attribute2.getName());
    Assertions.assertTrue(attribute2.getAttributeValues().size() == 1);
    Assertions.assertTrue(attribute2.getAttributeValues().get(0) instanceof PlaceOfBirthType);
    Assertions.assertEquals("Stockholm",
        ((PlaceOfBirthType) attribute2.getAttributeValues().get(0)).getValue());
  }

  @Test
  void testEidasNationality() {
    final NationalityType n = AttributeBuilder.createValueObject(NationalityType.TYPE_NAME, NationalityType.class);
    n.setValue("SE");

    final Attribute attribute = AttributeBuilder.builder(
            se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_NATIONALITY_ATTRIBUTE_NAME)
        .friendlyName(
            se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_NATIONALITY_ATTRIBUTE_FRIENDLY_NAME)
        .value(n)
        .build();

    final UserAttribute ua = new UserAttribute(attribute);

    Assertions.assertEquals(
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_NATIONALITY_ATTRIBUTE_NAME,
        ua.getId());
    Assertions.assertEquals(
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_NATIONALITY_ATTRIBUTE_FRIENDLY_NAME,
        ua.getFriendlyName());

    Assertions.assertTrue(ua.getValues().get(0) instanceof CountryString);
    Assertions.assertEquals("SE", ua.getValues().get(0).toString());

    final Attribute attribute2 = ua.toOpenSamlAttribute();
    Assertions.assertEquals(
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_NATIONALITY_ATTRIBUTE_NAME,
        attribute2.getName());
    Assertions.assertTrue(attribute2.getAttributeValues().size() == 1);
    Assertions.assertTrue(attribute2.getAttributeValues().get(0) instanceof NationalityType);
    Assertions.assertEquals("SE",
        ((NationalityType) attribute2.getAttributeValues().get(0)).getValue());
  }

  @Test
  void testEidasCountryOfResidence() {
    final CountryOfResidenceType v =
        AttributeBuilder.createValueObject(CountryOfResidenceType.TYPE_NAME, CountryOfResidenceType.class);
    v.setValue("SE");

    final Attribute attribute = AttributeBuilder.builder(
            se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_COUNTRY_OF_RESIDENCE_ATTRIBUTE_NAME)
        .friendlyName(
            se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_COUNTRY_OF_RESIDENCE_ATTRIBUTE_FRIENDLY_NAME)
        .value(v)
        .build();

    final UserAttribute ua = new UserAttribute(attribute);

    Assertions.assertEquals(
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_COUNTRY_OF_RESIDENCE_ATTRIBUTE_NAME,
        ua.getId());
    Assertions.assertEquals(
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_COUNTRY_OF_RESIDENCE_ATTRIBUTE_FRIENDLY_NAME,
        ua.getFriendlyName());

    Assertions.assertTrue(ua.getValues().get(0) instanceof CountryString);
    Assertions.assertEquals("SE", ua.getValues().get(0).toString());

    final Attribute attribute2 = ua.toOpenSamlAttribute();
    Assertions.assertEquals(
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_COUNTRY_OF_RESIDENCE_ATTRIBUTE_NAME,
        attribute2.getName());
    Assertions.assertTrue(attribute2.getAttributeValues().size() == 1);
    Assertions.assertTrue(attribute2.getAttributeValues().get(0) instanceof CountryOfResidenceType);
    Assertions.assertEquals("SE",
        ((CountryOfResidenceType) attribute2.getAttributeValues().get(0)).getValue());
  }

  @Test
  void testEidasCountryOfBirth() {
    final CountryOfBirthType v =
        AttributeBuilder.createValueObject(CountryOfBirthType.TYPE_NAME, CountryOfBirthType.class);
    v.setValue("SE");

    final Attribute attribute = AttributeBuilder.builder(
            se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_COUNTRY_OF_BIRTH_ATTRIBUTE_NAME)
        .friendlyName(
            se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_COUNTRY_OF_BIRTH_ATTRIBUTE_FRIENDLY_NAME)
        .value(v)
        .build();

    final UserAttribute ua = new UserAttribute(attribute);

    Assertions.assertEquals(
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_COUNTRY_OF_BIRTH_ATTRIBUTE_NAME,
        ua.getId());
    Assertions.assertEquals(
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_COUNTRY_OF_BIRTH_ATTRIBUTE_FRIENDLY_NAME,
        ua.getFriendlyName());

    Assertions.assertTrue(ua.getValues().get(0) instanceof CountryString);
    Assertions.assertEquals("SE", ua.getValues().get(0).toString());

    final Attribute attribute2 = ua.toOpenSamlAttribute();
    Assertions.assertEquals(
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_COUNTRY_OF_BIRTH_ATTRIBUTE_NAME,
        attribute2.getName());
    Assertions.assertTrue(attribute2.getAttributeValues().size() == 1);
    Assertions.assertTrue(attribute2.getAttributeValues().get(0) instanceof CountryOfBirthType);
    Assertions.assertEquals("SE",
        ((CountryOfBirthType) attribute2.getAttributeValues().get(0)).getValue());
  }

  @Test
  void testEidasTownOfBirth() {
    final Attribute attribute = AttributeBuilder.builder(
            se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_TOWN_OF_BIRTH_ATTRIBUTE_NAME)
        .friendlyName(
            se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_TOWN_OF_BIRTH_ATTRIBUTE_FRIENDLY_NAME)
        .value("Enköping")
        .build();

    final UserAttribute ua = new UserAttribute(attribute);

    Assertions.assertEquals(
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_TOWN_OF_BIRTH_ATTRIBUTE_NAME,
        ua.getId());
    Assertions.assertEquals(
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_TOWN_OF_BIRTH_ATTRIBUTE_FRIENDLY_NAME,
        ua.getFriendlyName());

    Assertions.assertTrue(ua.getValues().get(0) instanceof String);
    Assertions.assertEquals("Enköping", ua.getValues().get(0).toString());

    final Attribute attribute2 = ua.toOpenSamlAttribute();
    Assertions.assertEquals(
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_TOWN_OF_BIRTH_ATTRIBUTE_NAME,
        attribute2.getName());
    Assertions.assertTrue(attribute2.getAttributeValues().size() == 1);
    Assertions.assertTrue(attribute2.getAttributeValues().get(0) instanceof XSString);
    Assertions.assertEquals("Enköping",
        ((XSString) attribute2.getAttributeValues().get(0)).getValue());
  }

  @Test
  public void testEidasCurrentAddress() {

    final CurrentAddressType address = (CurrentAddressType) XMLObjectProviderRegistrySupport.getBuilderFactory()
        .getBuilder(CurrentAddressType.TYPE_NAME)
        .buildObject(CurrentAddressType.TYPE_NAME.getNamespaceURI(),
            CurrentAddressType.TYPE_NAME.getLocalPart(), "eidas");
    fillAddress(address);

    final Attribute attribute = AttributeBuilder.builder(
            se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_CURRENT_ADDRESS_ATTRIBUTE_NAME)
        .friendlyName(
            se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_CURRENT_ADDRESS_ATTRIBUTE_FRIENDLY_NAME)
        .value(address)
        .build();

    final UserAttribute ua = new UserAttribute(attribute);

    Assertions.assertEquals(
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_CURRENT_ADDRESS_ATTRIBUTE_NAME,
        ua.getId());
    Assertions.assertEquals(
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_CURRENT_ADDRESS_ATTRIBUTE_FRIENDLY_NAME,
        ua.getFriendlyName());

    Assertions.assertTrue(ua.getValues().get(0) instanceof CurrentAddress);
    Assertions.assertEquals(address.toSwedishEidString(), ua.getValues().get(0).toString());

    final Attribute attribute2 = ua.toOpenSamlAttribute();
    Assertions.assertEquals(
        se.swedenconnect.opensaml.eidas.ext.attributes.AttributeConstants.EIDAS_CURRENT_ADDRESS_ATTRIBUTE_NAME,
        attribute2.getName());
    Assertions.assertTrue(attribute2.getAttributeValues().size() == 1);
    Assertions.assertTrue(attribute2.getAttributeValues().get(0) instanceof CurrentAddressType);

    verifyAddress(address, (CurrentAddressType) attribute2.getAttributeValues().get(0));
  }

  private static void fillAddress(final CurrentAddressStructuredType address) {
    address.setLocatorDesignator("6 tr");
    address.setLocatorName("10");
    address.setThoroughfare("Korta gatan");
    address.setPostName("Solna");
    address.setPostCode("19174");
    address.setAdminunitFirstline("SE");
    address.setAdminunitSecondline("Uppland");
  }

  private static void verifyAddress(final CurrentAddressStructuredType expected,
      final CurrentAddressStructuredType actual) {
    Assertions.assertEquals(expected.getElementQName(), actual.getElementQName());
    Assertions.assertEquals(expected.getLocatorDesignator(), actual.getLocatorDesignator());
    Assertions.assertEquals(expected.getLocatorName(), actual.getLocatorName());
    Assertions.assertEquals(expected.getThoroughfare(), actual.getThoroughfare());
    Assertions.assertEquals(expected.getPostName(), actual.getPostName());
    Assertions.assertEquals(expected.getPostCode(), actual.getPostCode());

    Assertions.assertEquals(expected.getCvaddressArea(), actual.getCvaddressArea());
  }

}
