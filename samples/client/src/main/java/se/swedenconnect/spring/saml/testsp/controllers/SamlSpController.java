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
package se.swedenconnect.spring.saml.testsp.controllers;

import org.opensaml.saml.saml2.core.Assertion;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;
import se.swedenconnect.spring.saml.testsp.ext.DetailedSaml2Authentication;

import java.util.HashMap;
import java.util.Map;

/**
 * Main controller.
 */
@Controller
@RequestMapping("/")
public class SamlSpController extends BaseController {

  @Autowired
  MessageSource src;

  @GetMapping
  public ModelAndView home() {
    return new ModelAndView("home");
  }

  @GetMapping("/private/mypage")
  public ModelAndView myPage(final Saml2Authentication authn) {

    final Saml2AuthenticatedPrincipal p = (Saml2AuthenticatedPrincipal) authn.getPrincipal();
    final Map<String, String> attributes = new HashMap<>();
    p.getAttributes().forEach((key, value) -> attributes.put(key, value.get(0).toString()));

    final Assertion assertion = ((DetailedSaml2Authentication) authn).getAssertion();
    final String loa = assertion.getAuthnStatements().get(0).getAuthnContext().getAuthnContextClassRef().getURI();

    System.out.println(authn.getSaml2Response());

    final ModelAndView mav = new ModelAndView("mypage");
    mav.addObject("attributes", attributes);
    mav.addObject("loa", loa);

    SecurityContextHolder.clearContext();

    return mav;
  }

}
