package tz.co.simeon.spring.httpsignature;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.RequestEntity;
import org.springframework.util.MultiValueMap;
import lombok.Value;

@Value
public final class RequestSignageService {

  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  private final OutboundTargetDefinition config;

  public <T> RequestEntity<T> post(T body, HttpHeaders headers, URI uri) {
    try {
      addSignatureHeader(OBJECT_MAPPER.writeValueAsBytes(body), headers, uri);
    } catch (JsonProcessingException | GeneralSecurityException e) {
      e.printStackTrace();
    }
    return new RequestEntity<>(body, headers, HttpMethod.POST, uri);
  }

  private <T> MultiValueMap<String, String> addSignatureHeader(byte[] body, HttpHeaders headers,
      URI uri) throws JsonProcessingException, GeneralSecurityException {

    String digest = "SHA-256=" + Util.sha256Digest(new String(body, StandardCharsets.UTF_8));
    String currentTime = ZonedDateTime.now().format(DateTimeFormatter.RFC_1123_DATE_TIME);

    String cannonicalString = HttpSignature.createCannonicalRequestString(uri,
        headers.getContentType().toString(), body, currentTime, digest);

    byte[] signatureBytes = HttpSignature.signRsaSha256(
        cannonicalString.getBytes(StandardCharsets.UTF_8), config, Algorithm.RSA_SHA256_PSS);

    HttpSignature signature = new HttpSignature(config.keyId(), Algorithm.RSA_SHA256_PSS,
        CollectionsHelper.listOf(SignedHeadersConfig.REQUEST_TARGET, "host", "date", "digest",
            "content-type"),
        new String(Base64.getEncoder().encode(signatureBytes), StandardCharsets.US_ASCII));

    headers.add(HttpHeaders.AUTHORIZATION, "Signature " + signature.toSignatureHeader());
    headers.add("Date", currentTime);
    headers.add("Digest: ", digest);

    return headers;
  }

}
