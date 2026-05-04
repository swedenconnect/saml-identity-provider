# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Spring Security module that turns a Spring Boot application into a SAML 2 Identity Provider conforming
to the [Swedish eID Framework](https://docs.swedenconnect.se/technical-framework). Published to
Maven Central under `se.swedenconnect.spring.saml.idp`.

Java 21+, Spring Boot 4, Spring 7, OpenSAML 5. Build is multi-module Maven.

## Build / test commands

All commands run from the repository root.

| Action | Command |
| --- | --- |
| Full build (compile, test, install to local repo) | `mvn install` |
| Compile only, skip tests | `mvn install -DskipTests` |
| Run all tests in a module | `mvn test -pl saml-identity-provider` |
| Run a single test class | `mvn test -pl saml-identity-provider -Dtest=Saml2IdentityProviderVersionTest` |
| Run a single test method | `mvn test -pl saml-identity-provider -Dtest=ClassName#methodName` |
| Generate coverage report (per module) | `mvn test jacoco:report -pl saml-identity-provider` (open `target/site/jacoco/index.html`) |
| Build with sources, javadoc, and signing (release artefacts) | `mvn install -Prelease` |
| Run the demo IdP locally | `mvn spring-boot:run -pl samples/demo-boot-idp` |
| Run the sample SP that drives the demo IdP | `mvn spring-boot:run -pl samples/client` |

Notes:
- The Shibboleth Maven repository (`https://build.shibboleth.net/nexus/content/repositories/releases`)
  is declared in the parent POM and is required for OpenSAML artefacts.
- `maven-enforcer-plugin` enforces dependency convergence — version conflicts will fail the build.
- The `release` profile attaches sources/javadoc and signs with GPG; do not run it for normal development.

## Module layout

The parent POM (`pom.xml`, `groupId` `se.swedenconnect.spring.saml.idp`) aggregates four modules:

- **`saml-identity-provider/`** — Core library (`spring-saml-idp`). Contains all SAML protocol logic
  and Spring Security filters/configurers. Pure Spring Security; no Spring Boot dependency.
- **`autoconfigure/`** — Spring Boot autoconfiguration (`saml-idp-spring-boot-autoconfigure`). Reads
  `saml.idp.*` properties and wires the core library beans.
- **`starter/`** — Spring Boot starter (`saml-idp-spring-boot-starter`). Pulls in core + autoconfigure
  + `spring-boot-starter-web`. This is what consuming applications normally depend on.
- **`samples/`** — Two runnable Spring Boot apps:
  - `demo-boot-idp` — minimal IdP using the starter.
  - `client` — SAML SP that drives the demo IdP for manual end-to-end testing.

Version is hand-managed across all POMs and in `Saml2IdentityProviderVersion.java`. When bumping
versions, update every `pom.xml` and that class together.

## High-level architecture

The IdP plugs into Spring Security as a `SecurityFilterChain` declared by `Saml2IdpConfiguration`
(in `config/`). That filter chain is built by `Saml2IdpConfigurer`, an `AbstractHttpConfigurer`
that follows the Spring Security DSL pattern: it owns a set of nested **sub-configurers**, each
responsible for one slice of the protocol:

- `Saml2IdpMetadataEndpointConfigurer` — IdP metadata publication endpoint.
- `Saml2AuthnRequestProcessorConfigurer` — receives, decodes, and validates incoming `AuthnRequest`s.
- `Saml2UserAuthenticationConfigurer` — drives user authentication and assertion issuance.

Each sub-configurer installs one or more filters from `web/filters/` (e.g.
`Saml2AuthnRequestProcessingFilter`, `Saml2UserAuthenticationProcessingFilter`,
`Saml2IdpMetadataEndpointFilter`, `Saml2ErrorResponseProcessingFilter`).

### Request flow (happy path)

1. SP posts an `AuthnRequest`.
2. `Saml2AuthnRequestProcessingFilter` invokes `Saml2AuthnRequestAuthenticationProvider`, which
   validates the request and produces a `Saml2AuthnRequestAuthenticationToken`.
3. The token becomes the input to one or more `UserAuthenticationProvider` beans (in
   `authentication/provider/`). These are the **primary extension point** — applications supply
   one or more to actually authenticate the user. `AbstractUserAuthenticationProvider` and
   `UserRedirectAuthenticationProvider` (for redirect-based external authentication) are the
   intended base classes.
4. On success, `Saml2AssertionBuilder` builds the assertion, `Saml2ResponseBuilder` builds the
   response, and `Saml2ResponseSender` (via `ResponsePage`/`ThymeleafResponsePage`) POSTs the
   response back to the SP.

### External authentication (redirect-based)

`authentication/provider/external/` implements the redirect-and-resume pattern: a custom
`UserRedirectAuthenticationProvider` returns a `RedirectForAuthenticationToken`, the user is sent
to a controller (extending `AbstractAuthenticationController`), authenticates, and a
`ResumedAuthenticationToken` is delivered back through `ExternalAuthenticatorTokenRepository`
(default impl: `SessionBasedExternalAuthenticationRepository`).

### Configuration model

Settings are typed value objects in `settings/` (`IdentityProviderSettings`, `MetadataSettings`,
`CredentialSettings`, `EndpointSettings`, `AssertionSettings`, `MetadataProviderSettings`), all
extending `AbstractSettings`. The autoconfigure module maps `saml.idp.*` Spring Boot properties
(`IdentityProviderConfigurationProperties`) onto these settings beans.

`SsoVoter` (and built-in voters in `authentication/provider/`) decide whether a previous
authentication may be reused for SSO.

### Audit and events

- `audit/` — Spring Boot `AuditEvent` integration. `Saml2IdpAuditListener` listens for the
  framework's own `Saml2*Event`s and translates them to `Saml2AuditEvent`s. The `repository/`
  package provides interchangeable `AuditEventRepository` implementations: in-memory, file
  (with date-based rolling), Redis list, Redisson time-series, logger, plus delegating/filtering
  decorators.
- `events/` — typed `ApplicationEvent`s published via `Saml2IdpEventPublisher` for every
  significant lifecycle step (`Saml2AuthnRequestReceivedEvent`, `Saml2PreUserAuthenticationEvent`,
  `Saml2PostUserAuthenticationEvent`, `Saml2SuccessResponseEvent`, `Saml2ErrorResponseEvent`,
  `Saml2UnrecoverableErrorEvent`).

### Errors

Two error families:
- `Saml2ErrorStatusException` / `Saml2ErrorStatus` — recoverable: turned into a SAML response with
  an error status returned to the SP.
- `UnrecoverableSaml2IdpException` / `UnrecoverableSaml2IdpError` — cannot reach the SP (bad
  request, no `RelayState`, etc.); rendered to the user via the configured error view.

### Optional Redis

Redis is wired only when the consuming app provides Redis on the classpath. The Redis bits live
in `autoconfigure/.../redis/` and the `RedissonCondition`/`RedissonFilter` ensure autoconfig only
activates when actually requested (`saml.idp.session.module=redis`). The core library declares
`spring-data-redis` and `redisson` as `<optional>true</optional>`.

### Extensions

`extensions/` houses Swedish eID Framework specific protocol extensions (`SignatureMessageExtension`
for sign-service signature messages, `SadRequestExtension`, `UserMessageExtension`) and their
extractors/preprocessors. `attributes/release/` controls which attributes are released to which
SPs; `attributes/eidas/` and `attributes/nameid/` cover eIDAS and NameID generation.

## Conventions

- **Lombok is used throughout** (`@Slf4j`, `@Getter`/`@Setter`, etc.). Lombok 1.18.46 is on the
  classpath at `provided` scope.
- **Logging** uses SLF4J. Follow the level guidance in `~/.claude/CLAUDE.md` — in particular,
  rejected/invalid SAML requests are *expected* application behaviour and should be logged at
  INFO, not WARN.
- **Copyright header**: every Java file starts with the Apache 2.0 header `Copyright 2023-2026
  Sweden Connect`. Preserve it on edit; add it on new files.
- **OpenSAML bootstrapping**: tests extend `OpenSamlTestBase` (in
  `saml-identity-provider/src/test/java/.../OpenSamlTestBase.java`) which initialises OpenSAML
  once. New tests touching SAML objects should extend it.
- **Test stack**: JUnit 5 (Jupiter), Mockito, AssertJ. Integration tests live under
  `saml-identity-provider/src/test/java/.../it/`.
- **Public API surface** of the core library is the configurer DSL plus the `*Provider` /
  `*Repository` / `*Processor` extension interfaces — keep them stable and Javadoc-complete
  (`maven-javadoc-plugin` is configured with `doclint=all,-missing` in the release profile).

## Documentation

User-facing documentation lives under `docs/` and is published to
`https://docs.swedenconnect.se/saml-identity-provider/`. When adding or changing a
public-facing feature, update:
- `docs/configuration.md` — for new `saml.idp.*` properties or new configurer hooks.
- `docs/release-notes.md` — short bullet under the current version.
- `docs/audit.md` — for new audit event types or fields.
