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
package se.swedenconnect.spring.saml.idp.response;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.Response;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.util.StringUtils;

import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.codec.Base64Support;
import net.shibboleth.utilities.java.support.codec.EncodingException;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpError;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpException;

/**
 * A class for posting back a SAML {@link Response} to the client (Service Provider).
 *
 * @author Martin Lindström
 */
@Slf4j
public class Saml2ResponseSender {

  /** The response page. */
  private String responsePage;

  /** The redirect strategy. */
  private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

  /**
   * Directs the user agent to a page that issues a HTML POST containing the SAML response, and optionally, also the
   * {@code RelayState} variable.
   * 
   * @param httpServletRequest the HTTP servlet request
   * @param httpServletResponse the HTTP servlet response
   * @param destinationUrl the destination URL
   * @param response the SAML response
   * @param relayState the {@code RelayState}, may be {@code null}
   * @throws UnrecoverableSaml2IdpException for send errors
   */
  public void send(final HttpServletRequest httpServletRequest, final HttpServletResponse httpServletResponse,
      final String destinationUrl, final Response response, final String relayState)
      throws UnrecoverableSaml2IdpException {

    final String encodedResponse = this.encodeResponse(response);

    try {
      if (StringUtils.hasText(this.responsePage)) {
        final String redirectUrl = this.buildRedirectUrl(this.responsePage, destinationUrl, encodedResponse, relayState);
        this.redirectStrategy.sendRedirect(httpServletRequest, httpServletResponse, redirectUrl);
      }
      else {
        DefaultResponsePage.sendResponse(httpServletResponse, destinationUrl, encodedResponse, relayState);
      }
    }
    catch (final IOException/* | ServletException */ e) {
      log.error("Failed to send SAML Response to {} - {}", destinationUrl, e.getMessage(), e);
      throw new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.INTERNAL,
          "Failed to send Response message", e);
    }

  }

  /**
   * Assigns the path to a custom HTML page that posts the user back to the peer. If no page is assigned, 
   * the {@link DefaultResponsePage} will be used. The default page looks like:
   * 
   * <pre>
   * &lt;!DOCTYPE html&gt;
   * &lt;html lang="en"&gt;
   * &lt;head&gt;
   *   &lt;meta charset="utf-8"&gt;
   *   &lt;meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no"&gt;
   *   &lt;title&gt;SAML Response&lt;/title&gt;
   * &lt;/head&gt;
   * &lt;body onload="document.forms[0].submit()"&gt;
   *   &lt;form action="https://www.example.com/sso" method="POST"&gt;
   *     &lt;input type="hidden" name="SAMLResponse" value="..." /&gt;
   *     &lt;input type="hidden" name="RelayState" value="..." /&gt;
   *     &lt;noscript&gt;
   *       &lt;p/&gt;Your web browser does not have JavaScript enabled. Click the "Continue" button below to proceed.&lt;/p/&gt;
   *       &lt;p/&gt;&lt;input type="submit" value="Continue" /&gt;&lt;/p/&gt;
   *     &lt;/noscript/&gt;
   *   &lt;/form&gt;
   * &lt;/body&gt;
   * &lt;/html&gt;
   * </pre>
   * 
   * When a response has been configured, the user agent will be redirected to this page and the following query
   * parameters will be set:
   * <ul>
   * <li>{@code destination} - Contains the URL to include as the {@code action} parameter in the POST form.</li>
   * <li>{@code SAMLResponse} - Contains the encoded SAML response. Should be assigned the {@code SAMLResponse} form
   * parameter.</li>
   * <li>{@code RelayState} - Optional - If assigned, should be assigned the {@code RelayState} form parameter.</li>
   * </ul>
   * @param responsePage the response page
   */
  public void setResponsePage(final String responsePage) {
    this.responsePage = responsePage;
  }

  /**
   * Assigns a custom {@link RedirectStrategy} to use when redirecting to the configured response page. If not assigned
   * a {@link DefaultRedirectStrategy} is used.
   * 
   * @param redirectStrategy the strategy
   */
  public void setRedirectStrategy(final RedirectStrategy redirectStrategy) {
    this.redirectStrategy = Objects.requireNonNull(redirectStrategy, "redirectStrategy must not be null");
  }

  /**
   * Encodes the supplied {@link Response} message for being included in a HTML form.
   * 
   * @param samlResponse the response message
   * @return the Base64-encoding of the message
   * @throws UnrecoverableSaml2IdpException for encoding errors
   */
  protected String encodeResponse(final Response samlResponse) throws UnrecoverableSaml2IdpException {
    try {
      final String xml = SerializeSupport.nodeToString(XMLObjectSupport.marshall(samlResponse));
      return Base64Support.encode(xml.getBytes(StandardCharsets.UTF_8), Base64Support.UNCHUNKED);
    }
    catch (final MarshallingException | EncodingException e) {
      log.error("Failed to encode Response message - {} [destination: '{}', id: '{}', in-response-to: {}]",
          e.getMessage(), samlResponse.getDestination(), samlResponse.getID(), samlResponse.getInResponseTo(), e);

      throw new UnrecoverableSaml2IdpException(UnrecoverableSaml2IdpError.INTERNAL,
          "Failed to encode Response message", e);
    }
  }

  /**
   * Builds a redirect URL for sending the user agent to the configured response page.
   * 
   * @param url the response page
   * @param destination the POST destination URL
   * @param samlResponse the encoded SAML response
   * @param relayState the relay state (may be {@code null})
   * @return a redirect URL
   */
  protected String buildRedirectUrl(
      final String url, final String destination, final String samlResponse, final String relayState) {
    StringBuilder sb = new StringBuilder(url);
    sb.append(url.contains("?") ? '&' : '?').append("destination=")
        .append(URLEncoder.encode(destination, StandardCharsets.UTF_8))
        .append("&SAMLResponse=")
        .append(URLEncoder.encode(samlResponse, StandardCharsets.UTF_8));
    if (StringUtils.hasText(relayState)) {
      sb.append("&RelayState=" + URLEncoder.encode(relayState, StandardCharsets.UTF_8));
    }

    return sb.toString();
  }

}
