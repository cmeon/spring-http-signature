package tz.go.simeon.spring.httpsignature;

import java.util.Collections;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.util.Assert;
import lombok.Getter;
import lombok.NonNull;

/**
 * An {@link Authentication} that contains a
 * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Http Signature</a>.
 *
 * Used by {@link HttpSignatureAuthenticationFilter}.
 *
 * @author Josh Cummings
 * @author Simeon Mugisha
 * @since 5.1
 */
public class HttpSignatureAuthenticationToken extends AbstractAuthenticationToken {
  private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

  @Getter
  @NonNull
  private HttpSignature signature;

  @Getter
  private String name;

  @Getter
  private byte[] signedBytes;

  /**
   * Create a {@code HttpSignatureAuthenticationToken} using the provided parameter(s)
   * 
   * @param signature the Http Signature
   * @param request   the requests
   */
  public HttpSignatureAuthenticationToken(HttpSignature signature,
      ResettableStreamHttpServletRequest request) {
    super(Collections.emptyList());

    Assert.notNull(signature, "signature cannot be empty");

    this.signature = signature;

    this.signedBytes = signature.getHeaderBytesToSign(request, null);
  }

  public HttpSignatureAuthenticationToken(String name, Object signature) {
    super(Collections.emptyList());

    Assert.notNull(signature, "signature cannot be empty");

    this.signature = (HttpSignature) signature;
    this.name = name;
    this.setAuthenticated(true);
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public Object getCredentials() {
    return this.getSignature();
  }

  /**
   * {@inheritDoc}
   */
  @Override
  public Object getPrincipal() {
    return this.getSignature();
  }
}
