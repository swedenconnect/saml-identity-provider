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
package se.swedenconnect.spring.saml.idp.autoconfigure.settings;

import lombok.Getter;
import lombok.Setter;

import java.time.Duration;

/**
 * Configuration properties for assertion settings.
 * 
 * @author Martin Lindström
 */
public class AssertionSettingsConfigurationProperties {

  /**
   * Tells whether the Identity Provider encrypts assertions.
   */
  @Getter
  @Setter
  private Boolean encrypt;
  
  /**
   * A setting that tells the time restrictions the IdP puts on an Assertion concerning "not on or after".
   */
  @Getter
  @Setter
  private Duration notAfter;
  
  /**
   * A setting that tells the time restrictions the IdP puts on an Assertion concerning "not before".
   */
  @Getter
  @Setter
  private Duration notBefore;  
  
}
