package tz.co.simeon.spring.httpsignature;

/**
 * Headers supported by HTTP Signature.
 */
public enum HttpSignatureHeader {
  /**
   * Creates (or validates) a "Signature" header.
   */
  SIGNATURE,
  /**
   * Creates (or validates) an "Authorization" header, that contains "Signature" as the beginning of
   * its content (the rest of the header is the same as for {@link #SIGNATURE}.
   */
  AUTHORIZATION
}
