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
package se.swedenconnect.spring.saml.idp.utils;

import net.shibboleth.utilities.java.support.security.impl.RandomIdentifierGenerationStrategy;

/**
 * An implementation of the {@link Saml2MessageIDGenerator} based on Shibboleth's
 * {@link RandomIdentifierGenerationStrategy} that ensures that XML-safe identifiers are generated.
 * 
 * @author Martin Lindström
 */
public class DefaultSaml2MessageIDGenerator implements Saml2MessageIDGenerator {

  /** The underlying random generator. */
  private final RandomIdentifierGenerationStrategy generator;

  /**
   * Default constructor. Uses 16 bytes identifiers.
   */
  public DefaultSaml2MessageIDGenerator() {
    this(16);
  }

  /**
   * Constructor.
   * 
   * @param idSize the number of bytes used for the identifier
   */
  public DefaultSaml2MessageIDGenerator(final int idSize) {
    this.generator = new RandomIdentifierGenerationStrategy(idSize);
  }

  /** {@inheritDoc} */
  @Override
  public String generateIdentifier() {
    return this.generator.generateIdentifier();
  }

}
