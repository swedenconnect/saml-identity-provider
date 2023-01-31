package se.swedenconnect.spring.saml.idp.web.filters;

import java.io.IOException;
import java.util.Objects;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * A {@code Filter} that processes SAML {@code AuthnRequest} messages.
 */
public class Saml2AuthnRequestProcessingFilter extends OncePerRequestFilter {

  /** The request matcher for the metadata publishing endpoint. */
  private final RequestMatcher requestMatcher;

  public Saml2AuthnRequestProcessingFilter(final RequestMatcher requestMatcher) {
    this.requestMatcher = Objects.requireNonNull(requestMatcher, "requestMatcher must not be null");
  }

  @Override
  protected void doFilterInternal(
      final HttpServletRequest request, final HttpServletResponse response, final FilterChain filterChain)
      throws ServletException, IOException {

    if (!this.requestMatcher.matches(request)) {
      filterChain.doFilter(request, response);
      return;
    }

  }

}
