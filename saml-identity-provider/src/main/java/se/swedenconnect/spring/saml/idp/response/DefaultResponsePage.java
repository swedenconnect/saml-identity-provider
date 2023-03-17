/*
 * Copyright 2023 Sweden Connect
 *
 * Licensed under the Apache License, Version 2.0 (the "License").append(NEWLINE);
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

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.MediaType;
import org.springframework.util.StringUtils;

/**
 * A helper for creating the HTML page that posts the response back to the Service Provider.
 * 
 * @author Martin Lindström
 */
public class DefaultResponsePage implements ResponsePage {

  private static final MediaType TEXT_HTML_UTF8 = new MediaType("text", "html", StandardCharsets.UTF_8);
  private static final String NEWLINE = System.lineSeparator();

  /** {@inheritDoc} */
  @Override
  public void sendResponse(final HttpServletRequest httpServletRequest, final HttpServletResponse httpServletResponse,
      final String destination, final String samlResponse, final String relayState) throws IOException {
    final String responsePage = generateResponsePage(destination, samlResponse, relayState);

    httpServletResponse.setContentType(TEXT_HTML_UTF8.toString());
    httpServletResponse.setContentLength(responsePage.getBytes(StandardCharsets.UTF_8).length);
    httpServletResponse.setHeader("Cache-control", "no-cache, no-store");
    httpServletResponse.setHeader("Pragma", "no-cache");
    httpServletResponse.getWriter().write(responsePage);
  }

  /**
   * Generates a HTML page for posting the SAML response message.
   * 
   * @param destination the destination URL
   * @param samlResponse the Base64-encoded SAML response message
   * @param relayState the relay state (may be null)
   * @return a String containing the contents of the HTML page
   */
  public static String generateResponsePage(
      final String destination, final String samlResponse, final String relayState) {

    StringBuilder builder = new StringBuilder().append(NEWLINE);

    builder.append("<!DOCTYPE html>").append(NEWLINE);
    builder.append("<html lang=\"en\">").append(NEWLINE);
    builder.append("<head>").append(NEWLINE);
    builder.append("  <meta charset=\"utf-8\">").append(NEWLINE);
    builder.append("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, shrink-to-fit=no\">")
        .append(NEWLINE);
    builder.append("  <title>SAML Response</title>").append(NEWLINE);
    builder.append("</head>").append(NEWLINE);
    builder.append("<body onload=\"document.forms[0].submit()\">").append(NEWLINE);
    builder.append("  <form action=\"" + destination + "\" method=\"POST\">").append(NEWLINE);
    builder.append("    <input type=\"hidden\" name=\"SAMLResponse\" value=\"" + samlResponse + "\" />")
        .append(NEWLINE);
    if (StringUtils.hasText(relayState)) {
      builder.append("    <input type=\"hidden\" name=\"RelayState\" value=\"" + relayState + "\" />").append(NEWLINE);
    }
    builder.append("    <noscript>").append(NEWLINE);
    builder.append(
        "      <p>Your web browser does not have JavaScript enabled. Click the \"Continue\" button below to proceed.</p>")
        .append(NEWLINE);
    builder.append("      <p><input type=\"submit\" value=\"Continue\" /></p>").append(NEWLINE);
    builder.append("    </noscript>").append(NEWLINE);

    builder.append("  </form>").append(NEWLINE);
    builder.append("</body>").append(NEWLINE);
    builder.append("</html>").append(NEWLINE);

    return builder.toString();
  }

}
