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
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Base configurer for a SAML 2 component that exposes an endpoint (other than the default).
 *
 * @author Martin Lindström
 */
abstract class AbstractSaml2EndpointConfigurer extends AbstractSaml2Configurer {

  /**
   * Constructor.
   *
   * @param objectPostProcessor the object post processor.
   */
  AbstractSaml2EndpointConfigurer(final ObjectPostProcessor<Object> objectPostProcessor) {
    super(objectPostProcessor);
  }

  /**
   * Gets the request matcher for this configurer.
   *
   * @return the request matcher
   */
  abstract RequestMatcher getRequestMatcher();

}
