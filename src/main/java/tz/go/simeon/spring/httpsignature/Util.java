package tz.go.simeon.spring.httpsignature;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SignatureException;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Map;
import java.util.Optional;
import javax.servlet.http.HttpServletRequest;
import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;

public final class Util {
  public static Map<String, Collection<String>> headers(HttpServletRequest request) {
    Multimap<String, String> multimap = ArrayListMultimap.create();
    Enumeration<String> names = request.getHeaderNames();

    while (names.hasMoreElements()) {
      String name = names.nextElement();
      multimap.put(name, request.getHeader(name));
    }

    return multimap.asMap();
  }

  public static Optional<Collection<String>> values(HttpServletRequest request, String key) {
    Multimap<String, String> multimap = ArrayListMultimap.create();
    Enumeration<String> names = request.getHeaderNames();

    while (names.hasMoreElements()) {
      String name = names.nextElement();
      multimap.put(name, request.getHeader(name));
    }
    Collection<String> values = multimap.asMap().get(key.toLowerCase());
    return Optional.ofNullable(values);
  }

  public static String sha256Digest(String data) throws SignatureException {
    return getDigest("SHA-256", data, true);
  }

  private static String getDigest(String algorithm, String data, boolean toLower)
      throws SignatureException {
    try {
      MessageDigest mac = MessageDigest.getInstance(algorithm);
      mac.update(data.getBytes("UTF-8"));
      return toLower ? new String(toHex(mac.digest())).toLowerCase()
          : new String(toHex(mac.digest()));
    } catch (Exception e) {
      throw new SignatureException(e);
    }
  }

  private static String toHex(byte[] bytes) {
    BigInteger bi = new BigInteger(1, bytes);
    return String.format("%0" + (bytes.length << 1) + "X", bi);
  }
}
