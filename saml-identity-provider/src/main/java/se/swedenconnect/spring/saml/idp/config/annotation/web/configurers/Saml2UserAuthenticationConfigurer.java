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
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import se.swedenconnect.spring.saml.idp.authentication.DefaultSaml2AssertionHandler;
import se.swedenconnect.spring.saml.idp.response.Saml2ResponseHandler;
import se.swedenconnect.spring.saml.idp.settings.IdentityProviderSettings;
import se.swedenconnect.spring.saml.idp.web.filters.Saml2AuthnRequestProcessingFilter;
import se.swedenconnect.spring.saml.idp.web.filters.Saml2UserAuthenticationProcessingFilter;

public class Saml2UserAuthenticationConfigurer extends AbstractSaml2Configurer {
  
  /** The request matcher. */
  private RequestMatcher requestMatcher;

  /**
   * Constructor.
   * 
   * @param objectPostProcessor the object post processor
   */  
  Saml2UserAuthenticationConfigurer(final ObjectPostProcessor<Object> objectPostProcessor) {
    super(objectPostProcessor);
  }

  /** {@inheritDoc} */
  @Override
  void init(final HttpSecurity httpSecurity) {
    final IdentityProviderSettings settings = Saml2ConfigurerUtils.getIdentityProviderSettings(httpSecurity);
    this.requestMatcher = new OrRequestMatcher(
        new AntPathRequestMatcher(settings.getEndpoints().getRedirectAuthnEndpoint(), HttpMethod.GET.name()),
        new AntPathRequestMatcher(settings.getEndpoints().getPostAuthnEndpoint(), HttpMethod.POST.name()));    
  }

  /** {@inheritDoc} */
  @Override
  void configure(final HttpSecurity httpSecurity) {
    final IdentityProviderSettings settings = Saml2ConfigurerUtils.getIdentityProviderSettings(httpSecurity);
    final AuthenticationManager authenticationManager = httpSecurity.getSharedObject(AuthenticationManager.class);
    
    final Saml2UserAuthenticationProcessingFilter filter = new Saml2UserAuthenticationProcessingFilter(
        authenticationManager, this.getRequestMatcher(), new DefaultSaml2AssertionHandler(settings), 
        new Saml2ResponseHandler(settings));
    
    httpSecurity.addFilterAfter(this.postProcess(filter), Saml2AuthnRequestProcessingFilter.class);
  }

  /** {@inheritDoc} */
  @Override
  RequestMatcher getRequestMatcher() {
    return this.requestMatcher;
  }

}
