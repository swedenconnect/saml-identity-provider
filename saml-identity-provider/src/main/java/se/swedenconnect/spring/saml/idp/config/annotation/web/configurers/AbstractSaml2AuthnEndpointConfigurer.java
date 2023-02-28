/*
 * Copyright 2022 Sweden Connect
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

import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Base configurer for a SAML 2 component that services the authentication endpoints.
 *
 * @author Martin Lindström
 */
abstract class AbstractSaml2AuthnEndpointConfigurer extends AbstractSaml2Configurer {

  /**
   * Constructor.
   *
   * @param objectPostProcessor the object post processor.
   */
  AbstractSaml2AuthnEndpointConfigurer(final ObjectPostProcessor<Object> objectPostProcessor) {
    super(objectPostProcessor);
  }

  /** {@inheritDoc} */
  @Override
  final void init(final HttpSecurity httpSecurity) {
    this.init(httpSecurity, Saml2IdpConfigurerUtils.getAuthnEndpointsRequestMatcher(httpSecurity));
  }

  /**
   * Initializes the configurer.
   *
   * @param httpSecurity the HttpSecurity object
   * @param requestMatcher the {@link RequestMatcher} for this configurer
   */
  protected abstract void init(final HttpSecurity httpSecurity, final RequestMatcher requestMatcher);

}
