package tz.co.simeon.spring.httpsignature;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import lombok.Value;

@Value
public final class ResponseSignageService {
  private final OutboundTargetDefinition config;

  public <T> ResponseEntity<T> response(T body, MediaTypeMapper mapper, HttpStatus status) {
    return response(body, mapper, new HttpHeaders(), status);
  }

  public <T> ResponseEntity<T> response(T body, MediaTypeMapper mapper, HttpHeaders headers,
      HttpStatus status) {
    try {
      addSignatureHeader(mapper.getObjectMapper().writeValueAsBytes(body), mapper.getMediaType(),
          headers);
    } catch (JsonProcessingException | GeneralSecurityException e) {
      e.printStackTrace();
    }
    return new ResponseEntity<>(body, headers, status);
  }

  private <T> MultiValueMap<String, String> addSignatureHeader(byte[] body, MediaType mediaType,
      HttpHeaders headers) throws JsonProcessingException, GeneralSecurityException {

    String digest = "SHA-256=" + Util.sha256Digest(new String(body, StandardCharsets.UTF_8));
    String currentTime = ZonedDateTime.now().format(DateTimeFormatter.RFC_1123_DATE_TIME);

    String cannonicalString = HttpSignature.createCannonicalResponseString(mediaType.toString(),
        body, currentTime, digest);

    byte[] signatureBytes = HttpSignature.signRsaSha256(
        cannonicalString.getBytes(StandardCharsets.UTF_8), config, Algorithm.RSA_SHA256_PSS);

    HttpSignature signature = new HttpSignature(config.keyId(), Algorithm.RSA_SHA256_PSS,
        CollectionsHelper.listOf(SignedHeadersConfig.REQUEST_TARGET, "host", "date",
            "digest", "content-type"),
        new String(Base64.getEncoder().encode(signatureBytes), StandardCharsets.US_ASCII));

    System.out.printf("\n\n%s\n\n\n%s\n\n\n", new String(body, StandardCharsets.UTF_8),
        cannonicalString);

    headers.add("Signature", signature.toSignatureHeader());
    headers.add("Date", currentTime);
    headers.add("Digest: ", digest);
    headers.setContentType(mediaType);

    return headers;
  }

}
