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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * A response page for posting back SAML responses. The POST page typically looks like:
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
 * @author Martin Lindström
 */
public interface ResponsePage {

  /**
   * Sends a SAML Response message to the given destination.
   * 
   * @param httpServletRequest the HTTP servlet request (in case the implementation wants to redirect the user)
   * @param httpServletResponse the HTTP servlet response
   * @param destination the destination URL
   * @param samlResponse the Base64-encoded SAML response message
   * @param relayState the relay state (may be null)
   * @throws IOException for errors writing to the servlet response
   */
  void sendResponse(final HttpServletRequest httpServletRequest, final HttpServletResponse httpServletResponse,
      final String destination, final String samlResponse, final String relayState) throws IOException;

}
