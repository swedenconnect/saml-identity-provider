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
import java.nio.charset.StandardCharsets;
import java.util.Objects;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.MediaType;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.thymeleaf.context.WebContext;
import org.thymeleaf.spring5.SpringTemplateEngine;

import lombok.extern.slf4j.Slf4j;

/**
 * A {@link ResponsePage} implementation that uses a Thymeleaf template engine.
 * 
 * @author Martin Lindström
 */
@Slf4j
public class ThymeleafResponsePage implements ResponsePage {
  
  private static final MediaType TEXT_HTML_UTF8 = new MediaType("text", "html", StandardCharsets.UTF_8);

  /** The template engine. */
  private final SpringTemplateEngine templateEngine;

  /** The template id, for example "post.html". */
  private final String templateId;

  /**
   * Constructor.
   * 
   * @param templateEngine the template engine
   * @param templateId the template id, for example "post.html"
   */
  public ThymeleafResponsePage(final SpringTemplateEngine templateEngine, final String templateId) {
    this.templateEngine = Objects.requireNonNull(templateEngine, "templateEngine must not be null");
    this.templateId = templateId;
  }

  /** {@inheritDoc} */
  @Override
  public void sendResponse(final HttpServletResponse httpServletResponse,
      final String destination, final String samlResponse, final String relayState) throws IOException {
    
    log.debug("Invoking template to create POST body");

    final HttpServletRequest httpServletRequest = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
    
    final WebContext thymeleafContext = new WebContext(httpServletRequest, httpServletResponse, httpServletRequest.getServletContext()); 
    
    thymeleafContext.setVariable("action", destination);
    thymeleafContext.setVariable("SAMLResponse", samlResponse);
    if (relayState != null) {
      thymeleafContext.setVariable("RelayState", relayState);
    }
    httpServletResponse.setContentType(TEXT_HTML_UTF8.toString());
    httpServletResponse.setHeader("Cache-control", "no-cache, no-store");
    httpServletResponse.setHeader("Pragma", "no-cache");
    
    this.templateEngine.process(this.templateId, thymeleafContext, httpServletResponse.getWriter());
  }

}
