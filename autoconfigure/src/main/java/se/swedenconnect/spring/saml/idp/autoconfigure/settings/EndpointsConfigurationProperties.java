/*
 * Copyright 2022-2023 Sweden Connect
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

import lombok.Data;

/**
 * Configuration properties for endpoint configuration.
 *
 * @author Martin Lindström
 */
@Data
public class EndpointsConfigurationProperties {

  /**
   * The endpoint where the Identity Provider receives authentication requests via HTTP redirect.
   */
  private String redirectAuthn;

  /**
   * The endpoint where the Identity Provider receives authentication requests via HTTP POST.
   */
  private String postAuthn;

  /**
   * The endpoint where the Identity Provider receives authentication requests via HTTP redirect where Holder-of-key
   * (HoK) is used.
   */
  private String hokRedirectAuthn;

  /**
   * The endpoint where the Identity Provider receives authentication requests via HTTP POST where Holder-of-key
   * (HoK) is used.
   */
  private String hokPostAuthn;

  /**
   * The SAML metadata publishing endpoint.
   */
  private String metadata;

}
