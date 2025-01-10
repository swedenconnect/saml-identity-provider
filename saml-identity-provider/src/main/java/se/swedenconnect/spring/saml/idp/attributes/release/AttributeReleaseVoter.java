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

import java.util.function.BiFunction;

/**
 * {@link AttributeReleaseVoter}s are used by the {@link AttributeReleaseManager} to check if attributes returned from
 * {@link AttributeProducer}s should be released or not.
 *
 * @author Martin Lindström
 */
@FunctionalInterface
public interface AttributeReleaseVoter
    extends BiFunction<Saml2UserAuthentication, Attribute, AttributeReleaseVote> {

  /**
   * Maps to {@link #vote(Saml2UserAuthentication, Attribute)}.
   */
  @Override
  default AttributeReleaseVote apply(final Saml2UserAuthentication token, final Attribute attribute) {
    return this.vote(token, attribute);
  }

  /**
   * Tells whether this voter thinks that the supplied {@link Attribute} should be released or not.
   *
   * @param token the authentication token
   * @param attribute the attribute to vote on
   * @return an {@link AttributeReleaseVote}
   */
  AttributeReleaseVote vote(final Saml2UserAuthentication token, final Attribute attribute);

}
