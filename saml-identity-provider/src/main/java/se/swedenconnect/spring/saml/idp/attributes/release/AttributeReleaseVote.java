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
package se.swedenconnect.spring.saml.idp.attributes.release;

/**
 * An enumeration acting as the result for a {@link AttributeReleaseVoter}.
 * 
 * @author Martin Lindström
 */
public enum AttributeReleaseVote {
  
  /** The voter thinks that the attribute should be released. */
  INCLUDE,
  
  /** The voter thinks that the attribute must not be released. */ 
  DONT_INCLUDE,
  
  /** The voter has no opinion whether the attribute should be released. */
  DONT_KNOW;

}
