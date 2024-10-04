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
package se.swedenconnect.spring.saml.idp.utils;

/**
 * An interface for generating ID attributes for SAML objects.
 * <p>
 * From section 1.3.4 of <a href="https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf">Assertions and
 * Protocols for the OASIS Security Assertion Markup Language (SAML) V2.0</a>:
 * </p>
 * <p>
 * The {@code xs:ID} simple type is used to declare SAML identifiers for assertions, requests, and responses. Values
 * declared to be of type {@code xs:ID} in this specification MUST satisfy the following properties in addition to those
 * imposed by the definition of the {@code xs:ID} type itself:
 * </p>
 * <ul>
 * <li>Any party that assigns an identifier MUST ensure that there is negligible probability that that party or any
 * other party will accidentally assign the same identifier to a different data object.</li>
 * <li>Where a data object declares that it has a particular identifier, there MUST be exactly one such declaration.
 * </li>
 * </ul>
 * <p>
 * The mechanism by which a SAML system entity ensures that the identifier is unique is left to the implementation. In
 * the case that a random or pseudorandom technique is employed, the probability of two randomly chosen identifiers
 * being identical MUST be less than or equal to 2-128 and SHOULD be less than or equal to 2-160. This requirement MAY
 * be met by encoding a randomly chosen value between 128 and 160 bits in length. The encoding must conform to the rules
 * defining the {@code xs:ID} datatype. A pseudorandom generator MUST be seeded with unique material in order to ensure
 * the desired uniqueness properties between different systems.
 * </p>
 *
 * @author Martin Lindström
 */
public interface Saml2MessageIDGenerator {

  /**
   * Generates an identifier.
   *
   * @return an identifier
   */
  String generateIdentifier();

}
