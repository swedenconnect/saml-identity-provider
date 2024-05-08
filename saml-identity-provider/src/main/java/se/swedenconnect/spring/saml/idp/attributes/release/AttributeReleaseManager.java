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
package se.swedenconnect.spring.saml.idp.attributes.release;

import java.util.List;

/**
 * The {@code AttributeReleaseManager} is an {@link AttributeProducer} configured with a list of
 * {@link AttributeProducer}s and a list of {@link AttributeReleaseVoter}s. The manager will first invoke all
 * {@link AttributeProducer}s and for all attributes released invoke the {@link AttributeReleaseVoter}s.
 * <p>
 * The logic concerning the list of {@link AttributeReleaseVoter}s is as following:
 * </p>
 * <ul>
 * <li>If any of the voters vote {@link AttributeReleaseVote#DONT_INCLUDE} the attribute will not be released,</li>
 * <li>else, if at least of voter vote {@link AttributeReleaseVote#INCLUDE} the attribute will be released,</li>
 * <li>and finally, if all voters vote {@link AttributeReleaseVote#DONT_KNOW} the attribute will not be released.</li>
 * </ul>
 * 
 * @author Martin Lindström
 */
public interface AttributeReleaseManager extends AttributeProducer {

  /**
   * Gets an immutable list of all {@link AttributeProducer}s.
   * 
   * @return a list of {@link AttributeProducer}s
   */
  List<AttributeProducer> getAttributeProducers();

  /**
   * Gets an immutable list of all {@link AttributeReleaseVoter}s.
   * 
   * @return a list of {@link AttributeReleaseVoter}s
   */
  List<AttributeReleaseVoter> getAttributeReleaseVoters();

}
