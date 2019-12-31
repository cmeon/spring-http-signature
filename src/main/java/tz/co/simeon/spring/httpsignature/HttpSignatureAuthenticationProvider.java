package tz.co.simeon.spring.httpsignature;

import static tz.co.simeon.spring.httpsignature.CollectionsHelper.listOf;
import java.util.Optional;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * A provider that can authenticate incoming requests based on HTTP signature of header fields, and
 * can create signatures for outbound requests.
 */
@Getter
@RequiredArgsConstructor
public final class HttpSignatureAuthenticationProvider implements AuthenticationProvider {

  @NonNull
  private final HttpSignatureAuthenticationService service;

  static final SignedHeadersConfig DEFAULT_REQUIRED_HEADERS = SignedHeadersConfig.builder()
      .defaultConfig(SignedHeadersConfig.HeadersConfig
          .create(listOf("date", SignedHeadersConfig.REQUEST_TARGET)))
      .config(HttpMethod.GET.name(),
          SignedHeadersConfig.HeadersConfig.create(
              listOf(SignedHeadersConfig.REQUEST_TARGET, "host", "date"),
              listOf("authorization")))
      .config(HttpMethod.HEAD.name(),
          SignedHeadersConfig.HeadersConfig.create(
              listOf(SignedHeadersConfig.REQUEST_TARGET, "host", "date"),
              listOf("authorization")))
      .config(HttpMethod.DELETE.name(),
          SignedHeadersConfig.HeadersConfig.create(listOf(SignedHeadersConfig.REQUEST_TARGET,
              "host", "date", "digest", "content-type"), listOf("authorization")))
      .config(HttpMethod.PUT.name(),
          SignedHeadersConfig.HeadersConfig.create(listOf(SignedHeadersConfig.REQUEST_TARGET,
              "host", "date", "digest", "content-type"), listOf("authorization")))
      .config(HttpMethod.POST.name(),
          SignedHeadersConfig.HeadersConfig.create(listOf(SignedHeadersConfig.REQUEST_TARGET,
              "host", "date", "digest", "content-type"), listOf("authorization")))
      .build();

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    HttpSignatureAuthenticationToken token = (HttpSignatureAuthenticationToken) authentication;
    InboundClientConfig clientConfig = service.loadByKeyId(token.getSignature().getKeyId());

    if (!clientConfig.isEnabled()) {
      throw new HttpSignatureAuthenticationException("Key configuration is not enabled");
    }

    Optional<String> error = token.getSignature().verify(token.getSignedBytes(), clientConfig,
        DEFAULT_REQUIRED_HEADERS.headers(HttpMethod.POST.name()));

    if (error.isPresent()) {
      throw new HttpSignatureAuthenticationException(error.get());
    }
    return token;
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return HttpSignatureAuthenticationToken.class.isAssignableFrom(authentication);
  }

}
