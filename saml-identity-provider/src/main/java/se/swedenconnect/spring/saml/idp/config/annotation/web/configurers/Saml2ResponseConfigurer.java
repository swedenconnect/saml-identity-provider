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
package se.swedenconnect.spring.saml.idp.config.annotation.web.configurers;

import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import se.swedenconnect.spring.saml.idp.response.Saml2ResponseHandler;
import se.swedenconnect.spring.saml.idp.settings.IdentityProviderSettings;
import se.swedenconnect.spring.saml.idp.web.filters.Saml2AuthnRequestProcessingFilter;
import se.swedenconnect.spring.saml.idp.web.filters.Saml2ErrorResponseProcessingFilter;

/**
 * A configurer for producing SAML {@code Response} messages.
 * 
 * @author Martin Lindström
 */
public class Saml2ResponseConfigurer extends AbstractSaml2Configurer {

  /** The request matcher. */
  private RequestMatcher requestMatcher;

  /** Custom page returning the HTML response post page. */
  private String responsePage;

  /**
   * Constructor.
   * 
   * @param objectPostProcessor the post processor
   */
  Saml2ResponseConfigurer(final ObjectPostProcessor<Object> objectPostProcessor) {
    super(objectPostProcessor);
  }

  /**
   * Assigns a custom page that returns a HTML post page for sending SAML response messages. The default page looks
   * like:
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
   *     &lt;div&gt;
   *       &lt;input type="hidden" name="SAMLResponse" value="..." /&gt;
   *       &lt;input type="hidden" name="RelayState" value="..." /&gt;
   *     &lt;/div&gt;
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
   * 
   * @param responsePage the custom response page
   * @return the {@link Saml2ResponseConfigurer} for further configuration
   */
  public Saml2ResponseConfigurer responsePage(final String responsePage) {
    this.responsePage = responsePage;
    return this;
  }

  /** {@inheritDoc} */
  @Override
  void init(final HttpSecurity httpSecurity) {
    final IdentityProviderSettings settings = Saml2ConfigurerUtils.getIdentityProviderSettings(httpSecurity);
    this.requestMatcher = new OrRequestMatcher(
        new AntPathRequestMatcher(settings.getEndpoints().getRedirectAuthnEndpoint(), HttpMethod.GET.name()),
        new AntPathRequestMatcher(settings.getEndpoints().getPostAuthnEndpoint(), HttpMethod.POST.name()));
    // TODO: HoK endpoints
  }

  /** {@inheritDoc} */
  @Override
  void configure(final HttpSecurity httpSecurity) {
    final IdentityProviderSettings settings = Saml2ConfigurerUtils.getIdentityProviderSettings(httpSecurity);
    final Saml2ResponseHandler responseHandler = new Saml2ResponseHandler(settings);
    if (this.responsePage != null) {
      responseHandler.setResponsePage(this.responsePage);
    }
    
    final Saml2ErrorResponseProcessingFilter filter = 
        new Saml2ErrorResponseProcessingFilter(this.getRequestMatcher(), responseHandler);
    
    httpSecurity.addFilterBefore(postProcess(filter), Saml2AuthnRequestProcessingFilter.class);
  }

  /** {@inheritDoc} */
  @Override
  RequestMatcher getRequestMatcher() {
    return this.requestMatcher;
  }

}
