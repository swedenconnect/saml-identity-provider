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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Test cases for RequestedAttribute.
 * 
 * @author Martin Lindström
 */
public class RequestedAttributeTest {

  @Test
  public void testCtor1() {
    final RequestedAttribute ra = new RequestedAttribute("ID");
    Assertions.assertEquals("ID", ra.getId());
    Assertions.assertFalse(ra.isRequired());
    Assertions.assertNull(ra.getFriendlyName());
    Assertions.assertTrue(ra.getValues().isEmpty());
  }
  
  @Test
  public void testCtor2() {
    final RequestedAttribute ra = new RequestedAttribute("ID", "Friendly");
    Assertions.assertEquals("ID", ra.getId());
    Assertions.assertFalse(ra.isRequired());
    Assertions.assertEquals("Friendly", ra.getFriendlyName());
    Assertions.assertTrue(ra.getValues().isEmpty());
  }
  
  // The rest of the ctors are covered by the processor tests
  
}
