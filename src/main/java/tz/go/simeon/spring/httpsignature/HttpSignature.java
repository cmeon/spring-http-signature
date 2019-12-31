package tz.go.simeon.spring.httpsignature;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * Class wrapping signature and fields needed to build and validate it.
 */
@RequiredArgsConstructor
class HttpSignature {
  private static final String HEADER_SEPARATOR = ": ";
  private static final Logger LOGGER = Logger.getLogger(HttpSignature.class.getName());
  private static final List<String> DEFAULT_HEADERS = CollectionsHelper
      .listOf(SignedHeadersConfig.REQUEST_TARGET, "host", "x-tesws-date", "digest", "content-type");

  @Getter
  private final String keyId;

  @Getter
  private final Algorithm algorithm;

  private final List<String> headers;

  @Getter
  private String base64Signature;

  @Getter
  private byte[] signatureBytes;

  HttpSignature(String keyId, Algorithm algorithm, List<String> headers, String base64Signature) {
    this(keyId, algorithm, headers);
    this.base64Signature = base64Signature;
  }

  static HttpSignature fromHeader(String header) {
    /*
     * keyId="tesws-key-master-01",algorithm="rsa-sha256",
     * signature="Base64(RSA-SHA256(signing string))"
     */
    // required
    String keyId = null;
    // required
    String algorithm = null;
    // required
    String signature = null;

    // according to spec, I must go from beginning and latest one wins
    int b = 0;
    while (true) {
      int c = header.indexOf(',', b);
      int eq = header.indexOf('=', b);
      if (eq == -1) {
        return new HttpSignature(keyId, Algorithm.get(algorithm), DEFAULT_HEADERS, signature);
      }
      if (eq > c) {
        b = c + 1;
      }
      int qb = header.indexOf('"', eq);
      if (qb == -1) {
        return new HttpSignature(keyId, Algorithm.get(algorithm), DEFAULT_HEADERS, signature);
      }
      int qe = header.indexOf('"', qb + 1);
      if (qe == -1) {
        return new HttpSignature(keyId, Algorithm.get(algorithm), DEFAULT_HEADERS, signature);
      }

      String name = header.substring(b, eq).trim();
      String unquotedValue = header.substring(qb + 1, qe);
      switch (name) {
        case "keyId":
          keyId = unquotedValue;
          break;
        case "algorithm":
          algorithm = unquotedValue;
          break;
        case "signature":
          signature = unquotedValue;
          break;
        default:
          LOGGER.finest(
              () -> "Invalid signature header field: " + name + ": \"" + unquotedValue + "\"");
          break;

      }
      b = qe + 1;
      if (b >= header.length()) {
        return new HttpSignature(keyId, Algorithm.get(algorithm), DEFAULT_HEADERS, signature);
      }
    }
  }

  public HttpSignature sign(ResettableStreamHttpServletRequest request,
      OutboundTargetDefinition outboundDefinition, Map<String, Collection<String>> newHeaders) {

    HttpSignature signature = new HttpSignature(outboundDefinition.keyId(),
        outboundDefinition.algorithm(), outboundDefinition.signedHeadersConfig()
            .headers(request.getMethod(), Util.headers(request)));

    // validate algorithm is OK
    // let's try to validate the signature
    byte[] toBeSigned = getHeaderBytesToSign(request, newHeaders);

    signature.signatureBytes =
        signRsaSha256(toBeSigned, outboundDefinition, defaultSigningAlgorithm);

    signature.base64Signature = Base64.getEncoder().encodeToString(signature.signatureBytes);
    return signature;
  }

  /**
   * Create signature header
   *
   * @return
   */
  String toSignatureHeader() {
    // @formatter:off
    return
        "keyId=\"" + keyId + "\","
      + "algorithm=\"" + algorithm + "\","
      + "signature=\"" + base64Signature + "\"";
    // @formatter:on
  }

  List<String> getHeaders() {
    return Collections.unmodifiableList(headers);
  }

  Optional<String> validate() {
    List<String> problems = new ArrayList<>();

    if (null == keyId) {
      problems.add("keyId is a mandatory signature header component");
    }
    if (null == algorithm) {
      problems.add("algorithm is a mandatory signature header component");
    }
    if (null == base64Signature) {
      problems.add("signature is a mandatory signature header component");
    }

    try {
      this.signatureBytes = Base64.getDecoder().decode(base64Signature.getBytes());
    } catch (Exception e) {
      LOGGER.log(Level.FINEST, "Cannot get bytes from base64: " + base64Signature, e);
      problems.add("cannot get bytes from base64 encoded signature: " + e.getMessage());
    }

    if (problems.isEmpty()) {
      return Optional.empty();
    }
    return Optional.of("HttpSignature is not valid. Problems: " + String.join(", ", problems));
  }

  Optional<String> verify(byte[] signedBytes, InboundClientConfig clientDefinition,
      List<String> requiredHeaders) {

    for (String requiredHeader : requiredHeaders) {
      if (!this.headers.contains(requiredHeader)) {
        return Optional.of("Header " + requiredHeader + " is required, yet not signed");
      }
    }

    return verifyRsaSha256(signedBytes, clientDefinition, algorithm);
  }

  private static final Algorithm defaultSigningAlgorithm = Algorithm.RSA_SHA256_PSS;

  public static byte[] signRsaSha256(byte[] bytesToSign, OutboundTargetDefinition targetDefinition,
      Algorithm algorithm) {
    try {
      Signature signature = Signature.getInstance(algorithm.getPortableName(), "BC");
      signature
          .setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
      signature.initSign(targetDefinition.keyConfig()
          .orElseThrow(() -> new HttpSignatureException("Key config not found!")).privateKey()
          .orElseThrow(() -> new HttpSignatureException(
              "Private key is required, yet not " + "configured")));

      signature.update(bytesToSign);
      return signature.sign();
    } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException
        | NoSuchProviderException | InvalidAlgorithmParameterException e) {
      throw new HttpSignatureException(e);
    }
  }

  public Optional<String> verifyRsaSha256(byte[] signedBytes, InboundClientConfig clientDefinition,
      Algorithm algorithm) {
    try {
      Signature signature = Signature.getInstance(algorithm.getPortableName(), "BC");
      signature
          .setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
      signature.initVerify(clientDefinition.keyConfig()
          .orElseThrow(() -> new HttpSignatureException("Key config not found!")).publicKey()
          .orElseThrow(() -> new HttpSignatureException("Public key is required but not found!")));
      signature.update(signedBytes);

      boolean verified = signature.verify(this.signatureBytes);
      if (!verified) {
        return Optional.of("Signature is not valid");
      }

      return Optional.empty();
    } catch (NoSuchAlgorithmException e) {
      LOGGER.log(Level.FINEST, "SHA256withRSA algorithm not found", e);
      return Optional.of("SHA256withRSA algorithm not found: " + e.getMessage());
    } catch (InvalidKeyException e) {
      LOGGER.log(Level.FINEST, "Invalid RSA key", e);
      return Optional.of("Invalid RSA key: " + e.getMessage());
    } catch (SignatureException e) {
      LOGGER.log(Level.FINEST, "Signature exception", e);
      return Optional.of("SignatureException: " + e.getMessage());
    } catch (InvalidAlgorithmParameterException e) {
      LOGGER.log(Level.FINEST, "Signature exception", e);
      return Optional.of("Invalid algoritm: " + e.getMessage());
    } catch (NoSuchProviderException e) {
      LOGGER.log(Level.FINEST,
          "Bouncy Castle provider not found: (http://www.bouncycastle.org/wiki/display/JA1/Provider+Installation)",
          e);
      return Optional.of("Provider not found:" + e.getMessage());
    }
  }

  public byte[] getHeaderBytesToSign(ResettableStreamHttpServletRequest request,
      Map<String, Collection<String>> newHeaders) {
    try {
      return getSignedString(newHeaders, request).getBytes(StandardCharsets.UTF_8);
    } catch (NoSuchAlgorithmException | IOException | SignatureException e) {
      e.printStackTrace();
      return null;
    }
  }

  private String getSignedString(Map<String, Collection<String>> newHeaders,
      ResettableStreamHttpServletRequest request)
      throws NoSuchAlgorithmException, IOException, SignatureException {

    String message =
        request.getReader().lines().map(Function.identity()).collect(Collectors.joining("\n"));

    Map<String, Collection<String>> requestHeaders = Util.headers(request);

    return this.headers.stream().map(header -> {
      if ("(request-target)".equals(header)) {
        // special case
        return header + HEADER_SEPARATOR + request.getMethod().toLowerCase() + " "
            + request.getRequestURI();
      } else if ("digest".equals(header)) {
        // special case
        try {
          String sha256sum = Util.sha256Digest(message);
          return header + HEADER_SEPARATOR + "SHA-256=" + sha256sum;
        } catch (SignatureException e) {
          // TODO Auto-generated catch block
          e.printStackTrace();
          return null;
        }

      } else {
        Collection<String> headerValues = requestHeaders.get(header);
        if (null == headerValues && null == newHeaders) {
          // we do not support creation of new headers, just throw an exception
          throw new HttpSignatureException(
              "Header " + header + " is required for signature, yet not defined in " + "request");
        }
        if (null == headerValues) {
          // there are two headers we understand and may want to add to request
          if ("date".equalsIgnoreCase(header)) {
            String date = request.getHeader("x-tesws-date");
            // String date = ZonedDateTime.now(ZoneId.of("GMT")).format(DATE_FORMATTER);
            headerValues = CollectionsHelper.listOf(date);
            newHeaders.put("date", headerValues);

            LOGGER.finest(() -> "Added date header to request: " + date);
          } else if ("host".equalsIgnoreCase(header)) {
            URI uri = URI.create(request.getRequestURI());

            String host = uri.getHost() + ":" + uri.getPort();
            headerValues = CollectionsHelper.listOf(host);
            newHeaders.put("host", headerValues);

            LOGGER.finest(() -> "Added host header to request: " + host);
          } else {
            throw new HttpSignatureException(
                "Header " + header + " is required for signature, yet not defined in " + "request");
          }
        }

        return header + HEADER_SEPARATOR + String.join(" ", headerValues);
      }
    }).collect(Collectors.joining("\n"));
  }

  public static <T> String createCannonicalRequestString(URI uri, String contentType, byte[] body,
      String date, String digest) {
    // @formatter:off
   return Arrays.asList(
      "(request-target): "+uri.getPath(),
      "host: "+uri.getHost(),
      "x-tesws-date: "+date
      ,"digest: "+digest
      ,"content-type: "+contentType
    )
    .stream()
    .collect(Collectors.joining("\n"));
    // @formatter:on
  }

  public static <T> String createCannonicalResponseString(String contentType, byte[] body,
      String date, String digest) {
    // @formatter:off
   return Arrays.asList(
      "x-tesws-date: "+date
      ,"digest: "+digest
      ,"content-type: "+contentType
    )
    .stream()
    .collect(Collectors.joining("\n"));
    // @formatter:on
  }

}
