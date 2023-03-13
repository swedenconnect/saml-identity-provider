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
package se.swedenconnect.spring.saml.idp.demo.error;

import java.util.Map;

import javax.servlet.ServletException;

import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.web.servlet.error.DefaultErrorAttributes;
import org.springframework.boot.web.servlet.error.ErrorAttributes;
import org.springframework.web.context.request.WebRequest;

import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpError;
import se.swedenconnect.spring.saml.idp.error.UnrecoverableSaml2IdpException;

/**
 * An {@link ErrorAttributes} implementation that intercepts {@link UnrecoverableSaml2IdpException} and adds the
 * following items to the result of {@link #getErrorAttributes(WebRequest, ErrorAttributeOptions)}:
 * <ul>
 * <li>{@value #IDP_ERROR_CODE} - The enum name of the {@link UnrecoverableSaml2IdpError}.</li>
 * <li>{@value #IDP_ERROR_MESSAGE_CODE} - The message code describing the error
 * ({@link UnrecoverableSaml2IdpError#getMessageCode()}).</li>
 * <li>{@value #IDP_ERROR_DESCRIPTION} - The textual description ({@link UnrecoverableSaml2IdpError#getDescription()}).
 * Should be the fallback text if the above does not render a text.</li>
 * </ul>
 * 
 * @author Martin Lindström
 */
public class Saml2IdpErrorAttributes extends DefaultErrorAttributes {

  public static final String IDP_ERROR_CODE = "idpErrorCode";
  public static final String IDP_ERROR_MESSAGE_CODE = "idpErrorMessageCode";
  public static final String IDP_ERROR_DESCRIPTION = "idpErrorDescription";

  /** {@inheritDoc} */
  @Override
  public Map<String, Object> getErrorAttributes(final WebRequest webRequest, final ErrorAttributeOptions options) {

    final Map<String, Object> errorAttributes = super.getErrorAttributes(webRequest, options);

    Throwable error = this.getError(webRequest);
    if (error != null) {
      while (error instanceof ServletException && error.getCause() != null) {
        error = error.getCause();
      }
    }
    if (error != null && UnrecoverableSaml2IdpException.class.isInstance(error)) {
      final UnrecoverableSaml2IdpException samlError = UnrecoverableSaml2IdpException.class.cast(error);
      errorAttributes.put(IDP_ERROR_CODE, samlError.getError().toString());
      errorAttributes.put(IDP_ERROR_MESSAGE_CODE, samlError.getError().getMessageCode());
      errorAttributes.put(IDP_ERROR_DESCRIPTION, samlError.getError().getDescription());
    }

    return errorAttributes;
  }

}
