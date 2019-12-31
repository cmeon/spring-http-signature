package tz.go.simeon.spring.httpsignature;

import org.springframework.security.core.AuthenticationException;

public class UnsupportedAlgorithmException extends AuthenticationException {

  private static final long serialVersionUID = 1L;

  public UnsupportedAlgorithmException(final String message) {
    super(message);
  }

  public UnsupportedAlgorithmException(final String message, final Throwable cause) {
    super(message, cause);
  }
}
