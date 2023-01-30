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

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

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

    System.out.println(this.src.getMessage("sp.msg.back", null, new Locale("sv")));
    System.out.println(this.src.getMessage("sp.msg.back", null, new Locale("de")));
    System.out.println(this.src.getMessage("sp.msg.back", null, new Locale("dk")));

    final ModelAndView mav = new ModelAndView("home");
    return mav;
  }

  @GetMapping("/private/mypage")
  public ModelAndView myPage(final Saml2Authentication authn) {

    final Saml2AuthenticatedPrincipal p = (Saml2AuthenticatedPrincipal) authn.getPrincipal();
    final Map<String, String> attributes = new HashMap<>();
    p.getAttributes().entrySet().stream()
      .forEach(e -> attributes.put(e.getKey(), e.getValue().get(0).toString()));

    System.out.println(authn.getSaml2Response());

    final ModelAndView mav = new ModelAndView("mypage");
    mav.addObject("attributes", attributes);

    SecurityContextHolder.clearContext();

    return mav;
  }

}
