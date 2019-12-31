package tz.co.simeon.spring.httpsignature;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import org.springframework.http.MediaType;
import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public enum MediaTypeMapper {
  XML(MediaType.APPLICATION_XML, new XmlMapper()),

  JSON(MediaType.APPLICATION_JSON, new ObjectMapper());

  private MediaType mediaType;

  private ObjectMapper objectMapper;
}
