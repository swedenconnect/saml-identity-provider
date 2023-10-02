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
package se.swedenconnect.spring.saml.idp.autoconfigure.error;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import org.springframework.boot.autoconfigure.template.TemplateAvailabilityProvider;
import org.springframework.boot.autoconfigure.template.TemplateAvailabilityProviders;
import org.springframework.boot.autoconfigure.web.servlet.error.ErrorViewResolver;
import org.springframework.context.ApplicationContext;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.util.Assert;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.View;
import org.springframework.web.util.HtmlUtils;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpException;

/**
 * A SAML error view resolver for handling {@link UnrecoverableSaml2IdpException}.
 *
 * @author Martin Lindström
 */
public class Saml2IdpErrorViewResolver implements ErrorViewResolver, Ordered {

  private final ApplicationContext applicationContext;

  private final TemplateAvailabilityProviders templateAvailabilityProviders;

  private int order = Ordered.HIGHEST_PRECEDENCE;

  private String idpErrorViewName = "error/idp";

  /**
   * Constructor.
   *
   * @param applicationContext the application context
   */
  public Saml2IdpErrorViewResolver(final ApplicationContext applicationContext) {
    Assert.notNull(applicationContext, "ApplicationContext must not be null");
    this.applicationContext = applicationContext;
    this.templateAvailabilityProviders = new TemplateAvailabilityProviders(applicationContext);
  }

  /** {@inheritDoc} */
  @Override
  public int getOrder() {
    return this.order;
  }

  /**
   * Assigns the order for this bean.
   *
   * @param order the order
   */
  public void setOrder(final int order) {
    this.order = order;
  }

  /**
   * Assigns the view name for IdP errors. The default is {@code error/idp}.
   *
   * @param idpErrorViewName the view name
   */
  public void setIdpErrorViewName(final String idpErrorViewName) {
    this.idpErrorViewName = idpErrorViewName;
  }

  /** {@inheritDoc} */
  @Override
  public ModelAndView resolveErrorView(final HttpServletRequest request, final HttpStatus status,
      final Map<String, Object> model) {
    if (model.containsKey(Saml2IdpErrorAttributes.IDP_ERROR_CODE)) {
      final TemplateAvailabilityProvider provider =
          this.templateAvailabilityProviders.getProvider(this.idpErrorViewName, this.applicationContext);
      if (provider != null) {
        return new ModelAndView(this.idpErrorViewName, model);
      }
      return new ModelAndView(new IdpErrorStaticView(), model);
    }
    return null;
  }

  @Slf4j
  private static class IdpErrorStaticView implements View {

    private static final MediaType TEXT_HTML_UTF8 = new MediaType("text", "html", StandardCharsets.UTF_8);

    @Override
    public void render(final Map<String, ?> model, final HttpServletRequest request, final HttpServletResponse response)
        throws Exception {
      if (response.isCommitted()) {
        final String message = this.getMessage(model);
        log.error(message);
        return;
      }
      response.setContentType(TEXT_HTML_UTF8.toString());
      final StringBuilder builder = new StringBuilder();
      final Object timestamp = model.get("timestamp");
      final Object message = model.get("message");
      final Object trace = model.get("trace");
      final String idpError = (String) model.get(Saml2IdpErrorAttributes.IDP_ERROR_CODE);
      final String idpDescription = (String) model.get(Saml2IdpErrorAttributes.IDP_ERROR_DESCRIPTION);

      if (response.getContentType() == null) {
        response.setContentType(this.getContentType());
      }
      builder.append("<html><body><h1>IdP Error</h1>").append(
          "<p>This application has no explicit mapping for IdP errors, so you are seeing this as a fallback.</p>")
          .append("<div id='created'>").append(timestamp).append("</div>")
          .append("<div>There was an unexpected error (type=").append(this.htmlEscape(model.get("error")))
          .append(", status=").append(this.htmlEscape(model.get("status"))).append(").</div>");
      if (idpError != null) {
        builder.append("<div>").append(this.htmlEscape(idpError));
        if (idpDescription != null) {
          builder.append(" - ").append(this.htmlEscape(idpDescription));
        }
        builder.append("</div>");
      }
      if (message != null) {
        builder.append("<div>").append(this.htmlEscape(message)).append("</div>");
      }
      if (trace != null) {
        builder.append("<div style='white-space:pre-wrap;'>").append(this.htmlEscape(trace)).append("</div>");
      }
      builder.append("</body></html>");
      response.getWriter().append(builder.toString());
    }

    private String htmlEscape(final Object input) {
      return input != null ? HtmlUtils.htmlEscape(input.toString()) : null;
    }

    private String getMessage(final Map<String, ?> model) {
      final Object path = model.get("path");
      String message = "Cannot render error page for request [" + path + "]";
      if (model.get("message") != null) {
        message += " and exception [" + model.get("message") + "]";
      }
      message += " as the response has already been committed.";
      message += " As a result, the response may have the wrong status code.";
      return message;
    }

    @Override
    public String getContentType() {
      return "text/html";
    }

  }

}
