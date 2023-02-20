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
package se.swedenconnect.spring.saml.idp.autoconfigure.settings;

import java.time.Duration;

import lombok.Data;

/**
 * Configuration properties for assertion settings.
 * 
 * @author Martin Lindström
 */
@Data
public class AssertionSettingsConfigurationProperties {

  /**
   * Tells whether the Identity Provider encrypts assertions.
   */
  private Boolean encrypt;
  
  /**
   * A settings that tells the time restrictions the IdP puts on an Assertion concerning "not on or after".
   */
  private Duration notAfter;
  
  /**
   * A settings that tells the time restrictions the IdP puts on an Assertion concerning "not before".
   */
  private Duration notBefore;  
  
}
