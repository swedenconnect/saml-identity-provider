/*
 * Copyright 2023-2024 Sweden Connect
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
package se.swedenconnect.spring.saml.idp.config.configurers;

import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Base configurer for a SAML 2 component.
 *
 * @author Martin Lindström
 */
abstract class AbstractSaml2Configurer {

  /** The object post processor. */
  private final ObjectPostProcessor<Object> objectPostProcessor;

  /**
   * Constructor.
   *
   * @param objectPostProcessor the object post processor.
   */
  AbstractSaml2Configurer(final ObjectPostProcessor<Object> objectPostProcessor) {
    this.objectPostProcessor = objectPostProcessor;
  }

  /**
   * Initializes the configurer.
   *
   * @param httpSecurity the HttpSecurity object
   */
  abstract void init(final HttpSecurity httpSecurity);

  /**
   * Configures the {@link HttpSecurity} object.
   *
   * @param httpSecurity the HttpSecurity object to configure
   */
  abstract void configure(final HttpSecurity httpSecurity);

  /**
   * Gets the request matcher for this configurer. Note that if the configurer accepts requests from the endpoints for
   * receiving authentication requests ({@link Saml2IdpConfigurerUtils#getAuthnEndpointsRequestMatcher(HttpSecurity)})
   * this should not be returned.
   *
   * @return the request matcher, or {@code null} if no other endpoint than the authentication request is handled
   */
  abstract RequestMatcher getRequestMatcher();

  /**
   * Post processes the supplied object.
   *
   * @param <T> the type
   * @param object the object to process
   * @return the processed object
   */
  protected final <T> T postProcess(final T object) {
    return this.objectPostProcessor.postProcess(object);
  }

  /**
   * Gets the object post processor.
   *
   * @return the object post processor
   */
  protected final ObjectPostProcessor<Object> getObjectPostProcessor() {
    return this.objectPostProcessor;
  }

}
