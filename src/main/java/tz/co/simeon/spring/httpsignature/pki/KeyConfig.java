package tz.co.simeon.spring.httpsignature.pki;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;

/**
 * Configuration of keystore, certificates and keys. This class is not RSA specific, though it is
 * tested with RSA keys only.
 * <p>
 * Can be either built through a builder, or loaded from configuration.
 * <p>
 * Full configuration example (this class can be used to wrap either of: private key, public key,
 * public key certificate, and certification chain, and a list of certificates):
 * 
 * <pre>
 * # path to keystore (mandatory when loaded from config)
 * keystore-path = "src/test/resources/keystore.p12"
 * # Keystore type
 * # PKCS12 or JKS
 * # defaults to jdk default (PKCS12 for latest JDK)
 * keystore-type = "JKS"
 * # password of the keystore (optional, defaults to empty)
 * keystore-passphrase = "password"
 * # alias of the certificate to get public key from (mandatory if public key is needed or public cert is needed)
 * cert-alias = "service_cert"
 * # alias of the key to sign request (mandatory if private key is needed)
 * key-alias = "myPrivateKey"
 * # password of the private key (usually the same as keystore - that's how openssl does it)
 * # also defaults to keystore-passphrase
 * key-passphrase = "password"
 * # certification chain - will add certificates from this cert chain
 * cert-chain = "alias1"
 * # path to PEM file with a private key. May be encrypted, though only with PCKS#8. To get the correct format (e.g. from
 * # openssl generated encrypted private key), use the following command:
 * # openssl pkcs8 -topk8 -in ./id_rsa -out ./id_rsa.p8
 * key-path = "path/to/private/key"
 * # path to PEM file with certificate chain (may contain more than one certificate)
 * cert-chain-path = "path/to/cert/chain/path"
 * </pre>
 */
public final class KeyConfig {
  private final PrivateKey privateKey;
  private final PublicKey publicKey;
  private final X509Certificate publicCert;
  private final List<X509Certificate> certChain = new LinkedList<>();
  private final List<X509Certificate> certificates = new LinkedList<>();

  public KeyConfig(PrivateKey privateKey, PublicKey publicKey, X509Certificate publicCert,
      Collection<X509Certificate> certChain, Collection<X509Certificate> certificates) {

    this.privateKey = privateKey;
    this.publicKey = publicKey;
    this.publicCert = publicCert;
    this.certChain.addAll(certChain);
    this.certificates.addAll(certificates);
  }

  public KeyConfig(PublicKey publicKey) {
    this(null, publicKey, null, new LinkedList<>(), new LinkedList<>());
  }

  /**
   * The public key of this config if configured.
   *
   * @return the public key of this config or empty if not configured
   */
  public Optional<PublicKey> publicKey() {
    return Optional.ofNullable(publicKey);
  }

  /**
   * The private key of this config if configured.
   *
   * @return the private key of this config or empty if not configured
   */
  public Optional<PrivateKey> privateKey() {
    return Optional.ofNullable(privateKey);
  }

  /**
   * The public X.509 Certificate if configured.
   *
   * @return the public certificate of this config or empty if not configured
   */
  public Optional<X509Certificate> publicCert() {
    return Optional.ofNullable(publicCert);
  }

  /**
   * The X.509 Certificate Chain.
   *
   * @return the certificate chain or empty list if not configured
   */
  public List<X509Certificate> certChain() {
    return Collections.unmodifiableList(certChain);
  }

  /**
   * The X.509 Certificates.
   *
   * @return the certificates configured or empty list if none configured
   */
  public List<X509Certificate> certs() {
    return Collections.unmodifiableList(certificates);
  }
}
