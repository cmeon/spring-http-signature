package tz.go.simeon.spring.httpsignature;

import java.io.Serializable;
import java.util.Optional;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserCache;
import tz.go.simeon.spring.httpsignature.pki.KeyConfig;

/**
 * Provides core user information.
 *
 * <p>
 * Implementations are not used directly by Spring Security for security purposes. They simply store
 * user information which is later encapsulated into {@link Authentication} objects. This allows
 * non-security related user information (such as email addresses, telephone numbers etc) to be
 * stored in a convenient location.
 * <p>
 * Concrete implementations must take particular care to ensure the non-null contract detailed for
 * each method is enforced. See {@link org.springframework.security.core.userdetails.User} for a
 * reference implementation (which you might like to extend or use in your code).
 *
 * @see InboundClientConfig
 * @see UserCache
 *
 * @author Ben Alex
 */
public interface InboundClientConfig extends Serializable {
  /**
   * Key id of this service (will be mapped by target service to validate signature).
   *
   * @return key id string (may be an API key, key fingerprint, service name etc.)
   */
  public String keyId();

  /**
   * Algorithm used by this signature.
   *
   * @return algorithm
   */
  public Algorithm algorithm();

  /**
   * Private key configuration for RSA based algorithms.
   *
   * @return private key location and configuration or empty optional if not configured
   */
  public Optional<KeyConfig> keyConfig();

  /**
   * Shared secret for HMAC based algorithms.
   *
   * @return shared secret or empty optional if not configured
   */
  public Optional<byte[]> hmacSharedSecret();

  public boolean isEnabled();
}
