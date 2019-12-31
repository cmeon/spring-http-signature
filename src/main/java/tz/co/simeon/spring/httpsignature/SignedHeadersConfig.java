package tz.co.simeon.spring.httpsignature;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Configuration of required and "if-present" headers to be signed.
 * <p>
 * Example for configuration based approach:
 * 
 * <pre>
 * sign-headers: [
 *  # request may sign headers not specified here - only specify the ones that MUST be signed
 *  {
 *      # if method is not defined, then this is the default config
 *      # MUST be present and signed
 *      always = ["date"]
 *  }
 *  {
 *      method = "get"
 *      # MUST be present and signed
 *      always = ["date", "(request-target)", "host"]
 *      # MUST be signed IF present
 *      if-present = ["authorization"]
 *  }
 * ]
 * </pre>
 */
public final class SignedHeadersConfig {

  /**
   * Special header {@value} is used for method and path combination.
   */
  public static final String REQUEST_TARGET = "(request-target)";

  private final HeadersConfig defaultConfig;
  private final Map<String, HeadersConfig> methodConfigs;

  private SignedHeadersConfig(Builder builder) {
    this.defaultConfig = builder.defaultConfig;
    this.methodConfigs = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

    methodConfigs.putAll(builder.methodConfigs);
  }

  /**
   * Builder to create a new instance.
   *
   * @return new builder
   */
  public static Builder builder() {
    return new Builder().defaultConfig(HeadersConfig.create());
  }

  List<String> headers(String method, Map<String, Collection<String>> map) {
    return methodConfigs.getOrDefault(method, defaultConfig).getHeaders(map);
  }

  List<String> headers(String method) {
    return new ArrayList<>(methodConfigs.getOrDefault(method, defaultConfig).always);
  }

  /**
   * Fluent API builder to create {@link SignedHeadersConfig} instances. Call {@link #build()} to
   * create a new instance.
   */
  public static final class Builder {
    private static final HeadersConfig DEFAULT_HEADERS =
        HeadersConfig.create(CollectionsHelper.listOf("date"));

    private final Map<String, HeadersConfig> methodConfigs =
        new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    private HeadersConfig defaultConfig = DEFAULT_HEADERS;

    private Builder() {
    }

    public SignedHeadersConfig build() {
      return new SignedHeadersConfig(this);
    }

    /**
     * Default configuration is used by methods that do not have an explicit configuration.
     * <p>
     * <strong>Configuration is not cumulative - e.g. if you configure default to require "date" and
     * "host" headers and method "get" to require "(request-target)", get will NOT require "date"
     * and "host"</strong>
     *
     * @param config configuration of method (e.g. headers that must always be signed and headers to
     *               be signed when available in request)
     * @return updated builder instance
     */
    public Builder defaultConfig(HeadersConfig config) {
      this.defaultConfig = config;
      return this;
    }

    /**
     * Configuration of a single method to set required and "if-present" headers to be signed (or to
     * be expected in inbound signature).
     *
     * @param method method name (methods are case-insensitive)
     * @param config configuration of method
     * @return updated builder instance
     */
    public Builder config(String method, HeadersConfig config) {
      this.methodConfigs.put(method, config);
      return this;
    }
  }

  /**
   * Configuration of headers to be signed.
   */
  public static final class HeadersConfig {
    private final List<String> always;
    private final List<String> ifPresent;

    private HeadersConfig(List<String> requiredHeaders, List<String> ifPresentHeaders) {
      this.always = new ArrayList<>(requiredHeaders);
      this.ifPresent = new LinkedList<>(ifPresentHeaders);
    }

    /**
     * Create a config with no signed headers (e.g. signatures disabled)
     *
     * @return instance with no required headers
     */
    public static HeadersConfig create() {
      return create(CollectionsHelper.listOf());
    }

    /**
     * Create a config with required headers only (e.g. no "if-present" headers).
     *
     * @param requiredHeaders headers that must be signed
     * @return instance with required headers
     */
    public static HeadersConfig create(List<String> requiredHeaders) {
      return create(requiredHeaders, CollectionsHelper.listOf());
    }

    /**
     * Create a new instance with both required headers and headers that are signed only if present
     * in request.
     *
     * @param requiredHeaders  headers that must be signed (and signature validation or creation
     *                         should fail if not signed or present)
     * @param ifPresentHeaders headers that must be signed if present in request
     * @return instance with required and "if-present" headers
     */
    public static HeadersConfig create(List<String> requiredHeaders,
        List<String> ifPresentHeaders) {
      return new HeadersConfig(requiredHeaders, ifPresentHeaders);
    }

    List<String> getHeaders(Map<String, Collection<String>> map) {
      List<String> result = new ArrayList<>(always);

      ifPresent.stream().filter(map::containsKey).forEach(result::add);

      return result;
    }
  }

}
