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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Default implementation of the {@link AttributeReleaseManager} interface.
 *
 * @author Martin Lindström
 */
public class DefaultAttributeReleaseManager implements AttributeReleaseManager {

  /** The attribute producers. */
  private final List<AttributeProducer> producers;

  /** The attribute release voters. */
  private final List<AttributeReleaseVoter> voters;

  /**
   * Constructor.
   *
   * @param producers the list of producers
   * @param voters the list of voters (if none is supplied, an "include-all" voter is used)
   */
  public DefaultAttributeReleaseManager(final List<AttributeProducer> producers,
      final List<AttributeReleaseVoter> voters) {
    this.producers = Optional.ofNullable(producers)
        .filter(p -> !p.isEmpty())
        .orElseThrow(() -> new IllegalArgumentException("At least on producer must be provided"));

    this.voters = Optional.ofNullable(voters)
        .filter(v -> !v.isEmpty())
        .orElseGet(() -> List.of(new IncludeAllAttributeReleaseVoter()));
  }

  /** {@inheritDoc} */
  @Override
  public List<Attribute> releaseAttributes(final Saml2UserAuthentication userAuthentication) {
    final List<Attribute> attributes = new ArrayList<>();
    for (final AttributeProducer p : this.producers) {
      final List<Attribute> pattrs = p.releaseAttributes(userAuthentication);
      pattrs.forEach((attr) -> {
        if (attributes.stream().noneMatch(a -> Objects.equals(a.getName(), attr.getName()))) {

          // Ask the voters to see if we should include this attribute ...
          //
          AttributeReleaseVote vote = AttributeReleaseVote.DONT_KNOW;
          for (final AttributeReleaseVoter voter : this.voters) {
            final AttributeReleaseVote v = voter.vote(userAuthentication, attr);
            if (v == AttributeReleaseVote.DONT_INCLUDE) {
              vote = AttributeReleaseVote.DONT_INCLUDE;
              break;
            }
            else if (v == AttributeReleaseVote.INCLUDE) {
              vote = AttributeReleaseVote.INCLUDE;
            }
          }

          if (vote == AttributeReleaseVote.INCLUDE) {
            attributes.add(attr);
          }
        }
      });
    }

    return attributes;
  }

  /** {@inheritDoc} */
  @Override
  public List<AttributeProducer> getAttributeProducers() {
    return Collections.unmodifiableList(this.producers);
  }

  /** {@inheritDoc} */
  @Override
  public List<AttributeReleaseVoter> getAttributeReleaseVoters() {
    return Collections.unmodifiableList(this.voters);
  }

}
