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
package se.swedenconnect.spring.saml.idp.utils;

import java.io.Serializable;

import org.apache.commons.lang3.SerializationUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;

import lombok.Getter;
import se.swedenconnect.opensaml.OpenSAMLInitializer;
import se.swedenconnect.opensaml.OpenSAMLSecurityDefaultsConfig;
import se.swedenconnect.opensaml.OpenSAMLSecurityExtensionConfig;
import se.swedenconnect.opensaml.xmlsec.config.DefaultSecurityConfiguration;

/**
 * Test cases for SerializableOpenSamlObject.
 * 
 * @author Martin Lindström
 */
public class SerializableOpenSamlObjectTest {
  
  @BeforeAll
  public static void initializeOpenSAML() throws Exception {
    final OpenSAMLInitializer bootstrapper = OpenSAMLInitializer.getInstance();
    if (!bootstrapper.isInitialized()) {
      bootstrapper.initialize(
          new OpenSAMLSecurityDefaultsConfig(new DefaultSecurityConfiguration()),
          new OpenSAMLSecurityExtensionConfig());
    }
  }  

  @Test
  public void testSerializeDeserialize() {
    
    final Issuer issuer = (Issuer) XMLObjectSupport.buildXMLObject(Issuer.DEFAULT_ELEMENT_NAME);
    issuer.setValue("https://idp.example.com");
    issuer.setFormat(NameID.ENTITY);

    final TestObject obj1 = new TestObject("sample text", issuer);

    final TestObject obj2 = SerializationUtils.roundtrip(obj1);

    Assertions.assertEquals(obj1.getText(), obj2.getText());
    Assertions.assertEquals(obj1.getIssuer().getValue(), obj2.getIssuer().getValue());
    Assertions.assertEquals(obj1.getIssuer().getFormat(), obj2.getIssuer().getFormat());
  }

  public static class TestObject implements Serializable {

    private static final long serialVersionUID = -56880659229972600L;

    @Getter
    private String text;
    
    private SerializableOpenSamlObject<Issuer> issuer; 

    public TestObject(final String text, final Issuer issuer) {
      this.text = text;
      this.issuer = new SerializableOpenSamlObject<Issuer>(issuer);
    }
    
    public Issuer getIssuer() {
      return this.issuer.get();
    }

  }

}
