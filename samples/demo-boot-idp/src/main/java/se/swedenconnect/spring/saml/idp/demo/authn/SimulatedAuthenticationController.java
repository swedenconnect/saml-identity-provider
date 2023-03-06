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

import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import se.swedenconnect.spring.saml.idp.authentication.provider.ExternalAuthenticationRepository;
import se.swedenconnect.spring.saml.idp.authentication.provider.RedirectForAuthenticationToken;
import se.swedenconnect.spring.saml.idp.demo.SimulatedUser;
import se.swedenconnect.spring.saml.idp.demo.UsersConfigurationProperties;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatus;
import se.swedenconnect.spring.saml.idp.error.Saml2ErrorStatusException;

@Controller
public class SimulatedAuthenticationController {
  
  public static final String AUTHN_PATH = "/authn";

  @Autowired
  private ExternalAuthenticationRepository externalAuthenticationRepository;

  @Autowired
  UsersConfigurationProperties userProps;

  @Autowired
  UserDetailsService userDetailsService;

  // TODO: Build a HandlerMethodArgumentResolver that injects input token
  // Check:
  // https://www.petrikainulainen.net/programming/spring-framework/spring-from-the-trenches-creating-a-custom-handlermethodargumentresolver/

  @GetMapping(AUTHN_PATH)
  public ModelAndView authenticate(final HttpServletRequest request, final HttpServletResponse response) {
    final ModelAndView mav = new ModelAndView("simulated");
    mav.addObject("users",
        this.userProps.getUsers().stream().map(SimulatedUser::getUsername).collect(Collectors.toList()));
    return mav;
  }

  @PostMapping("/authn/complete")
  public ModelAndView complete(final HttpServletRequest request, final HttpServletResponse response,
      @RequestParam(name = "username") final String userName) {
    
    final RedirectForAuthenticationToken redirectToken =
        this.externalAuthenticationRepository.getExternalAuthenticationToken(request);

    try {
      UserDetails details = this.userDetailsService.loadUserByUsername(userName);
      final SimulatedUser user = (SimulatedUser) this.userDetailsService.loadUserByUsername(userName);      
      this.externalAuthenticationRepository.completeExternalAuthentication(new SimulatedAuthentication(user), request);
    }
    catch (final UsernameNotFoundException e) {
      this.externalAuthenticationRepository.completeExternalAuthentication(
          new Saml2ErrorStatusException(Saml2ErrorStatus.UNKNOWN_PRINCIPAL), request);
    }

    return new ModelAndView("redirect:" + redirectToken.getResumeAuthnPath());
  }

}
