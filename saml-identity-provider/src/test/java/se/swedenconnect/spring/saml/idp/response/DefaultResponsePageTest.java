/*
 * Copyright 2023-2026 Sweden Connect
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

import java.util.ArrayList;
import java.util.List;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Attribute;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Test cases for DefaultResponsePage.
 *
 * @author Martin Lindström
 */
public class DefaultResponsePageTest {

  private static final String DESTINATION = "https://www.example.com/sso";

  private static final String SAML_RESPONSE = "RESPONSE";

  private static final String RELAY_STATE = "RELAY-STATE";

  @Test
  public void testGenerateResponsePage() throws Exception {

    final String page =
        DefaultResponsePage.generateResponsePage(DESTINATION, SAML_RESPONSE, RELAY_STATE);

    final Document html = Jsoup.parse(page);
    final Element formElement = html.getElementsByTag("form").stream()
        .findFirst()
        .orElse(null);

    Assertions.assertNotNull(formElement, "Not a POST form");

    final String destination = formElement.attr("action");
    Assertions.assertEquals(DESTINATION, destination);

    final String samlResponse = formElement.getElementsByAttributeValue("name", "SAMLResponse").stream()
        .map(e -> e.attr("value"))
        .findFirst()
        .orElse(null);

    Assertions.assertNotNull(samlResponse, "Missing SAMLResponse");
    Assertions.assertEquals(SAML_RESPONSE, samlResponse);

    final String receivedRelayState = formElement.getElementsByAttributeValue("name", "RelayState").stream()
        .map(e -> e.attr("value"))
        .findFirst()
        .orElse(null);

    Assertions.assertNotNull(receivedRelayState, "Missing RelayState");
    Assertions.assertEquals(RELAY_STATE, receivedRelayState);
  }

  /**
   * Relay state values containing characters that are significant in HTML must end up as the literal value of the
   * {@code RelayState} field, and must not change the structure of the page.
   */
  @ParameterizedTest
  @ValueSource(strings = {
      "\" onmouseover=\"x",
      "'",
      "\">text",
      "</form><form action=\"https://www.other.com/\">",
      "a&b",
      "&amp;",
      "&lt;p&gt;",
      "&#34;",
      "a\"b'c<d>e&f",
      "<!-- comment -->",
      "value with spaces",
      "aaaåäöЖ中"
  })
  public void testRelayStateIsWrittenAsLiteralValue(final String relayState) throws Exception {

    final Element form = assertStructureAndGetForm(
        DefaultResponsePage.generateResponsePage(DESTINATION, SAML_RESPONSE, relayState));

    Assertions.assertEquals(DESTINATION, form.attr("action"));
    Assertions.assertEquals(SAML_RESPONSE, getFieldValue(form, "SAMLResponse"));
    Assertions.assertEquals(relayState, getFieldValue(form, "RelayState"));
  }

  /**
   * The destination and the SAML response are written to the page in the same way as the relay state.
   */
  @Test
  public void testDestinationAndResponseAreWrittenAsLiteralValues() throws Exception {

    final String destination = "https://www.example.com/sso?a=1&b=2\" x=\"y";
    final String samlResponse = "<not-really-base64>\"&'";

    final Element form = assertStructureAndGetForm(
        DefaultResponsePage.generateResponsePage(destination, samlResponse, RELAY_STATE));

    Assertions.assertEquals(destination, form.attr("action"));
    Assertions.assertEquals(samlResponse, getFieldValue(form, "SAMLResponse"));
    Assertions.assertEquals(RELAY_STATE, getFieldValue(form, "RelayState"));
  }

  /**
   * A relay state that is already entity encoded is written as the literal characters given, i.e. the encoding is not
   * undone.
   */
  @Test
  public void testAlreadyEncodedRelayStateIsNotDecoded() throws Exception {

    final Element form = assertStructureAndGetForm(
        DefaultResponsePage.generateResponsePage(DESTINATION, SAML_RESPONSE, "&quot;&amp;&#39;"));

    Assertions.assertEquals("&quot;&amp;&#39;", getFieldValue(form, "RelayState"));
  }

  /**
   * Non-ASCII characters in the relay state are preserved.
   */
  @Test
  public void testNonAsciiRelayStateIsPreserved() throws Exception {

    final String relayState = "åäö-中文-😀";

    final Element form = assertStructureAndGetForm(
        DefaultResponsePage.generateResponsePage(DESTINATION, SAML_RESPONSE, relayState));

    Assertions.assertEquals(relayState, getFieldValue(form, "RelayState"));
  }

  /**
   * No relay state field is written if no relay state is given.
   */
  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(strings = { " ", "\t" })
  public void testNoRelayState(final String relayState) throws Exception {

    final String page = DefaultResponsePage.generateResponsePage(DESTINATION, SAML_RESPONSE, relayState);

    final Element form = Jsoup.parse(page).getElementsByTag("form").stream()
        .findFirst()
        .orElseThrow(() -> new AssertionError("Not a POST form"));

    Assertions.assertTrue(form.getElementsByAttributeValue("name", "RelayState").isEmpty(),
        "Expected no RelayState field");
    Assertions.assertEquals(SAML_RESPONSE, getFieldValue(form, "SAMLResponse"));
  }

  /**
   * Asserts that the given page has the same structure, i.e. the same elements with the same attributes, as a page
   * generated from values that contain no characters of significance in HTML, and that it contains exactly one form.
   *
   * @param page the page to check
   * @return the form element of the page
   */
  private static Element assertStructureAndGetForm(final String page) {

    final Document expected = Jsoup.parse(
        DefaultResponsePage.generateResponsePage(DESTINATION, SAML_RESPONSE, RELAY_STATE));
    final Document actual = Jsoup.parse(page);

    Assertions.assertEquals(structure(expected), structure(actual), "Unexpected page structure");

    Assertions.assertEquals(1, actual.getElementsByTag("form").size(), "Expected exactly one form");

    return actual.getElementsByTag("form").first();
  }

  /**
   * Gets the value of the hidden field having the given name.
   *
   * @param form the form element
   * @param name the field name
   * @return the field value, or null if no such field exists
   */
  private static String getFieldValue(final Element form, final String name) {
    return form.getElementsByAttributeValue("name", name).stream()
        .map(e -> e.attr("value"))
        .findFirst()
        .orElse(null);
  }

  /**
   * Describes the structure of a page as a list of its elements and their attribute names. Attribute values are left
   * out, since they are what the test cases vary.
   *
   * @param document the parsed page
   * @return the description of the page structure
   */
  private static List<String> structure(final Document document) {
    final List<String> elements = new ArrayList<>();
    for (final Element element : document.getAllElements()) {
      final List<String> attributes = element.attributes().asList().stream()
          .map(Attribute::getKey)
          .sorted()
          .toList();
      elements.add(element.tagName() + attributes);
    }
    return elements;
  }

}
