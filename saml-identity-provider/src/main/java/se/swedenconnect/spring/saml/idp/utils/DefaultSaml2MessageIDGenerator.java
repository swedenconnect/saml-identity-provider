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
package se.swedenconnect.spring.saml.idp.utils;

import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;

import org.apache.commons.codec.binary.Hex;

import net.shibboleth.shared.security.RandomIdentifierParameterSpec;
import net.shibboleth.shared.security.impl.RandomIdentifierGenerationStrategy;

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
    this.generator = new RandomIdentifierGenerationStrategy();
  }

  /**
   * Constructor.
   *
   * @param idSize the number of bytes used for the identifier
   */
  public DefaultSaml2MessageIDGenerator(final int idSize) {
    try {
      this.generator = new RandomIdentifierGenerationStrategy(
          new RandomIdentifierParameterSpec(new SecureRandom(), idSize, new Hex()));
    }
    catch (final InvalidAlgorithmParameterException e) {
      throw new RuntimeException(e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public String generateIdentifier() {
    return this.generator.generateIdentifier();
  }

}
