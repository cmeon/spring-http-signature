package tz.co.simeon.spring.httpsignature;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import javax.servlet.ReadListener;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

public class ResettableStreamHttpServletRequest extends HttpServletRequestWrapper {
  private byte[] rawData;
  private HttpServletRequest request;
  private ResettableServletInputStream servletStream;

  public ResettableStreamHttpServletRequest(HttpServletRequest request) {
    super(request);
    this.request = request;
    this.servletStream = new ResettableServletInputStream();
  }

  public void resetInputStream() {
    servletStream.stream = new ByteArrayInputStream(rawData);
  }

  @Override
  public ServletInputStream getInputStream() throws IOException {
    if (rawData == null) {
      rawData = toByteArray(this.request.getInputStream());
      servletStream.stream = new ByteArrayInputStream(rawData);
    }
    return servletStream;
  }

  @Override
  public BufferedReader getReader() throws IOException {
    if (rawData == null) {
      rawData = toByteArray(this.request.getInputStream());
      servletStream.stream = new ByteArrayInputStream(rawData);
    }
    String encoding = getCharacterEncoding();
    if (encoding != null) {
      return new BufferedReader(new InputStreamReader(servletStream, encoding));
    }
    return new BufferedReader(new InputStreamReader(servletStream, StandardCharsets.UTF_8));
  }

  private static byte[] toByteArray(InputStream in) throws IOException {
    ByteArrayOutputStream os = new ByteArrayOutputStream();

    byte[] buffer = new byte[1024];
    int len;

    // read bytes from the input stream and store them in buffer
    while ((len = in.read(buffer)) != -1) {
      // write bytes from the buffer into output stream
      os.write(buffer, 0, len);
    }

    return os.toByteArray();
  }

  private class ResettableServletInputStream extends ServletInputStream {
    private InputStream stream;
    private ReadListener listener = null;

    @Override
    public int read() throws IOException {
      return stream.read();
    }

    @Override
    public boolean isFinished() {
      try {
        return stream.available() != 0;
      } catch (IOException e) {
        e.printStackTrace();
        return true;
      }
    }

    @Override
    public boolean isReady() {
      return isFinished();
    }

    @Override
    public void setReadListener(ReadListener listener) {
      this.listener = listener;
      if (!isFinished()) {
        try {
          this.listener.onDataAvailable();
        } catch (IOException e) {
          this.listener.onError(e);
        }
        return;
      }
      try {
        this.listener.onAllDataRead();
      } catch (IOException e) {
        this.listener.onError(e);
      }
    }
  }
}
