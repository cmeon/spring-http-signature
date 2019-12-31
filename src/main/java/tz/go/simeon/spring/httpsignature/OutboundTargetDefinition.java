package tz.go.simeon.spring.httpsignature;

import java.util.Optional;
import lombok.RequiredArgsConstructor;
import tz.go.simeon.spring.httpsignature.pki.KeyConfig;

/**
 * Configuration of outbound target to sign outgoing requests.
 */
@RequiredArgsConstructor
public final class OutboundTargetDefinition {
  private final String keyId;
  private final Algorithm algorithm;
  private final KeyConfig keyConfig;
  private final HttpSignatureHeader header;
  private final byte[] hmacSharedSecret;
  private final SignedHeadersConfig signedHeadersConfig;


  /**
   * Key id of this service (will be mapped by target service to validate signature).
   *
   * @return key id string (may be an API key, key fingerprint, service name etc.)
   */
  public String keyId() {
    return keyId;
  }

  /**
   * Algorithm used by this signature.
   *
   * @return algorithm
   */
  public Algorithm algorithm() {
    return algorithm;
  }

  /**
   * Private key configuration for RSA based algorithms.
   *
   * @return private key location and configuration or empty optional if not configured
   */
  public Optional<KeyConfig> keyConfig() {
    return Optional.ofNullable(keyConfig);
  }

  /**
   * Shared secret for HMAC based algorithms.
   *
   * @return shared secret or empty optional if not configured
   */
  public Optional<byte[]> hmacSharedSecret() {
    return Optional.ofNullable(hmacSharedSecret);
  }

  /**
   * Header to store signature in.
   *
   * @return header type
   */
  public HttpSignatureHeader header() {
    return header;
  }

  /**
   * Configuration of method to headers to define headers to be signed.
   * <p>
   * The following headers have special handling:
   * <ul>
   * <li>date - if not present and required, will be added to request</li>
   * <li>host - if not present and required, will be added to request from target URI</li>
   * <li>(request-target) - as per spec, calculated from method and path</li>
   * <li>authorization - if {@link #header()} returns {@link HttpSignatureHeader#AUTHORIZATION} it
   * is ignored</li>
   * </ul>
   *
   * @return configuration of headers to be signed
   */
  public SignedHeadersConfig signedHeadersConfig() {
    return signedHeadersConfig;
  }
}
