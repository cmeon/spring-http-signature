package tz.co.simeon.spring.httpsignature.pki;

/**
 * Exception caused by PKI handling (keystores, keys, certificates).
 */
public class PkiException extends RuntimeException {
  private static final long serialVersionUID = 1L;

  public PkiException(String message) {
    super(message);
  }

  public PkiException(String message, Throwable cause) {
    super(message, cause);
  }
}