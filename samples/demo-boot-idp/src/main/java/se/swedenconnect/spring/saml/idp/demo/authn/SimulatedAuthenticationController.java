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
package se.swedenconnect.spring.saml.idp.demo.authn;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Setter;
import se.swedenconnect.spring.saml.idp.authentication.provider.external.AbstractAuthenticationController;
import se.swedenconnect.spring.saml.idp.demo.user.SimulatedUser;
import se.swedenconnect.spring.saml.idp.demo.user.UsersConfigurationProperties;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatus;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;

/**
 * The controller handling user authentication.
 *
 * @author Martin Lindström
 */
@Controller
public class SimulatedAuthenticationController
    extends AbstractAuthenticationController<SimulatedAuthenticationProvider> {

  public static final String AUTHN_PATH = "/authn";

  /** The authentication provider that is the "manager" for this authentication. */
  @Setter
  @Autowired
  private SimulatedAuthenticationProvider provider;

  /** The simualted users. */
  @Autowired
  UsersConfigurationProperties userProps;

  /** The user details service. */
  @Autowired
  UserDetailsService userDetailsService;

  /**
   * The entry point for the user authentication.
   *
   * @param request the HTTP servlet request
   * @param response the HTTP servlet response
   * @return a {@link ModelAndView}
   */
  @GetMapping(AUTHN_PATH)
  public ModelAndView authenticate(final HttpServletRequest request, final HttpServletResponse response) {
    final ModelAndView mav = new ModelAndView("simulated");
    mav.addObject("users", this.userProps.getUsers());
    return mav;
  }

  /**
   * When the user has "authenticated", the browser is posted back to this entry point to complete the authentication.
   *
   * @param request the HTTP servlet request
   * @param response the HTTP servlet response
   * @param userName the user name of the simulated user
   * @param action the action
   * @return a {@link ModelAndView} that redirects the browser back to the Spring Security flow
   */
  @PostMapping("/authn/complete")
  public ModelAndView complete(final HttpServletRequest request, final HttpServletResponse response,
      @RequestParam(name = "username") final String userName, @RequestParam("action") final String action) {

    if ("cancel".equals(action)) {
      return this.cancel(request);
    }
    else if ("NONE".equals(userName)) {
      return this.authenticate(request, response);
    }
    else {
      try {
        final SimulatedUser user = (SimulatedUser) this.userDetailsService.loadUserByUsername(userName);
        return this.complete(request, new SimulatedAuthenticationToken(user));
      }
      catch (final UsernameNotFoundException e) {
        return this.complete(request, new Saml2ErrorStatusException(Saml2ErrorStatus.UNKNOWN_PRINCIPAL));
      }
    }
  }

  /** {@inheritDoc} */
  @Override
  protected SimulatedAuthenticationProvider getProvider() {
    return this.provider;
  }

}
