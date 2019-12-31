package tz.go.simeon.spring.httpsignature;

import java.security.Signature;
import java.util.HashMap;
import java.util.Map;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum Algorithm {

  // rsa
  RSA_SHA256("SHA256withRSA", "rsa-sha256", Signature.class),

  RSA_SHA256_PSS("SHA256withRSA/PSS", "rsa-sha256-pss", Signature.class);

  private static final Map<String, Algorithm> aliases = new HashMap<>();

  static {
    for (final Algorithm algorithm : Algorithm.values()) {
      aliases.put(normalize(algorithm.getJmvName()), algorithm);
      aliases.put(normalize(algorithm.getPortableName()), algorithm);
    }
  }

  private final String portableName;
  private final String jmvName;
  private final Class<Signature> type;

  public static String toPortableName(final String name) {
    return get(name).getPortableName();
  }

  public static String toJvmName(final String name) {
    return get(name).getJmvName();
  }

  public static Algorithm get(String name) {
    final Algorithm algorithm = aliases.get(normalize(name));

    if (algorithm != null)
      return algorithm;

    throw new UnsupportedAlgorithmException(name + " algorithm is not supported.");
  }

  private static String normalize(String algorithm) {
    return algorithm.replaceAll("[^A-Za-z0-9]+", "").toLowerCase();
  }


  @Override
  public String toString() {
    return getJmvName();
  }
}
