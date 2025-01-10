/*
 * Copyright 2023-2025 Sweden Connect
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
package se.swedenconnect.spring.saml.idp.attributes.release;

import org.opensaml.saml.saml2.core.Attribute;
import se.swedenconnect.spring.saml.idp.authentication.Saml2UserAuthentication;

import java.util.List;

/**
 * An interface that is used to decide which attributes that should be released in an {@code Assertion}.
 *
 * @author Martin Lindström
 */
@FunctionalInterface
public interface AttributeProducer {

  /**
   * Determines which attributes to release based on the supplied token.
   *
   * @param userAuthentication the user authentication token
   * @return a (possibly empty) list of attributes
   */
  List<Attribute> releaseAttributes(final Saml2UserAuthentication userAuthentication);

}
