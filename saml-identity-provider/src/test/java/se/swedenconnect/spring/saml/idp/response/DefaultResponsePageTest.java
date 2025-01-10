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
package se.swedenconnect.spring.saml.idp.response;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Test cases for DefaultResponsePage.
 *
 * @author Martin Lindström
 */
public class DefaultResponsePageTest {

  @Test
  public void testGenerateResponsePage() throws Exception {

    final String page =
        DefaultResponsePage.generateResponsePage("https://www.example.com/sso", "RESPONSE", "RELAY-STATE");

    final Document html = Jsoup.parse(page);
    final Element formElement = html.getElementsByTag("form").stream()
        .findFirst()
        .orElse(null);

    Assertions.assertNotNull(formElement, "Not a POST form");

    final String destination = formElement.attr("action");
    Assertions.assertEquals("https://www.example.com/sso", destination);

    final String samlResponse = formElement.getElementsByAttributeValue("name", "SAMLResponse").stream()
        .map(e -> e.attr("value"))
        .findFirst()
        .orElse(null);

    Assertions.assertNotNull(samlResponse, "Missing SAMLResponse");
    Assertions.assertEquals("RESPONSE", samlResponse);

    final String receivedRelayState = formElement.getElementsByAttributeValue("name", "RelayState").stream()
        .map(e -> e.attr("value"))
        .findFirst()
        .orElse(null);

    Assertions.assertNotNull(receivedRelayState, "Missing RelayState");
    Assertions.assertEquals("RELAY-STATE", receivedRelayState);
  }

}
