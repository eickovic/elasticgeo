/**
 * This file is hereby placed into the Public Domain. This means anyone is
 * free to do whatever they wish with this file.
 */
package mil.nga.giat.data.elasticsearch;

import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.nio.client.HttpAsyncClientBuilder;
import org.apache.http.ssl.SSLContextBuilder;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestClientBuilder;
import org.geotools.data.DataStore;
import org.geotools.data.DataStoreFactorySpi;

import mil.nga.giat.data.elasticsearch.ElasticDataStore.ArrayEncoding;
import org.geotools.data.Parameter;

import java.awt.RenderingHints.Key;
import java.io.IOException;
import java.io.Serializable;
import java.io.UncheckedIOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Data store factory that creates {@linkplain ElasticDataStore} instances.
 *
 */
public class ElasticDataStoreFactory implements DataStoreFactorySpi {

    /** Cluster hostnames. **/
    public static final Param HOSTNAME = new Param("elasticsearch_host", String.class,
            "Host(s) with optional HTTP scheme and port.", false, "localhost");

    /** Cluster client port. **/
    public static final Param HOSTPORT = new Param("elasticsearch_port", Integer.class,
            "Default HTTP port. Ignored if the host includes the port.", false, 9200);

    /** UserName for Elasticsearch login*/
    public static final Param USER = new Param("user", String.class,
            "UserName for Elasticsearch authentication.", false, null);

    /** UserName for Elasticsearch login*/
    public static final Param PASSWD = new Param( "passwd", String.class,
            "Password used to login to Elasticsearch.",false, null,
                    Collections.singletonMap(Parameter.IS_PASSWORD, Boolean.TRUE));

    public static final Param SSL_ENABLED = new Param("ssl_enabled", Boolean.class,
            "Use https instead of http scheme. Ignored if the host includes the HTTP scheme.", false, false);

    public static final Param SSL_REJECT_UNAUTHORIZED = new Param("ssl_reject_unauthorized", Boolean.class,
            "Whether to validate the server certificate during the SSL handshake for https connections", false, false);

    /** Index name. **/
    public static final Param INDEX_NAME = new Param("index_name", String.class, "Index defining type (supports wildcard)", true);

    public static final Param DEFAULT_MAX_FEATURES = new Param("default_max_features", Integer.class, "Default max features", false, 100);

    public static final Param SOURCE_FILTERING_ENABLED = new Param("source_filtering_enabled", Boolean.class, "Enable source field filtering", false, false);

    public static final Param SCROLL_ENABLED = new Param("scroll_enabled", Boolean.class, "Use scan search type instead of dfs_query_then_fetch", false, false);

    public static final Param SCROLL_SIZE = new Param("scroll_size", Long.class, "Scroll size (ignored if scroll_enabled=false)", false, 20);

    public static final Param SCROLL_TIME_SECONDS = new Param("scroll_time", Integer.class, "Time to keep the scroll open in seconds (ignored if scroll_enabled=false)", false, 120);

    public static final Param ARRAY_ENCODING = new Param("array_encoding", String.class, "Array encoding strategy. Allowed values are \"JSON\" (keep arrays) "
            + " and \"CSV\" (URL encode and join array elements).", false, "JSON");

    public static final Param GRID_SIZE = new Param("grid_size", Long.class, "Hint for Geohash grid size (nrow*ncol)", false, 10000l);

    public static final Param GRID_THRESHOLD = new Param("grid_threshold",  Double.class,
            "Geohash grid aggregation precision will be the minimum necessary to satisfy actual_grid_size/grid_size>grid_threshold", false, 0.05);

    protected static final Param[] PARAMS = {
            HOSTNAME,
            HOSTPORT,
            USER,
            PASSWD,
            SSL_ENABLED,
            SSL_REJECT_UNAUTHORIZED,
            INDEX_NAME,
            DEFAULT_MAX_FEATURES,
            SOURCE_FILTERING_ENABLED,
            SCROLL_ENABLED,
            SCROLL_SIZE,
            SCROLL_TIME_SECONDS,
            ARRAY_ENCODING,
            GRID_SIZE,
            GRID_THRESHOLD
    };

    protected static final String DISPLAY_NAME = "Elasticsearch";

    protected static final String DESCRIPTION = "Elasticsearch Index";

    @Override
    public String getDisplayName() {
        return DISPLAY_NAME;
    }

    @Override
    public String getDescription() {
        return DESCRIPTION;
    }

    @Override
    public Param[] getParametersInfo() {
        return PARAMS;
    }

    @Override
    public boolean canProcess(Map<String, Serializable> params) {
        boolean result = false;
        try {
            final String searchHost = (String) HOSTNAME.lookUp(params);
            final String indexName = (String) INDEX_NAME.lookUp(params);
            final Integer hostport = (Integer) HOSTPORT.lookUp(params);

            if (searchHost != null && hostport != null && indexName != null) {
                result = true;
            }
        } catch (IOException e) {
            // ignore
        }
        return result;
    }

    @Override
    public boolean isAvailable() {
        return true;
    }

    @Override
    public Map<Key, ?> getImplementationHints() {
        return null;
    }

    @Override
    public DataStore createDataStore(Map<String, Serializable> params) throws IOException {
        final String indexName = (String) INDEX_NAME.lookUp(params);
        final String arrayEncoding = (String) getValue(ARRAY_ENCODING, params);

        final ElasticDataStore dataStore = new ElasticDataStore(createRestClient(params), indexName);
        dataStore.setDefaultMaxFeatures((Integer) getValue(DEFAULT_MAX_FEATURES, params));
        dataStore.setSourceFilteringEnabled((Boolean) getValue(SOURCE_FILTERING_ENABLED, params));
        dataStore.setScrollEnabled((Boolean)getValue(SCROLL_ENABLED, params));
        dataStore.setScrollSize(((Number)getValue(SCROLL_SIZE, params)).longValue());
        dataStore.setScrollTime((Integer)getValue(SCROLL_TIME_SECONDS, params));
        dataStore.setArrayEncoding(ArrayEncoding.valueOf(arrayEncoding.toUpperCase()));
        dataStore.setGridSize((Long) GRID_SIZE.lookUp(params));
        dataStore.setGridThreshold((Double) GRID_THRESHOLD.lookUp(params));
        return dataStore;
    }

    protected RestClient createRestClient(Map<String, Serializable> params) throws IOException {
        final String[] hosts = ((String) getValue(HOSTNAME, params)).split(",");
        final Integer defaultPort = (Integer) getValue(HOSTPORT, params);
        final String user = (String) getValue(USER, params);
        final String passwd = (String) getValue(PASSWD, params);
        Boolean sslEnabled = (Boolean) getValue(SSL_ENABLED, params);
        final Boolean sslRejectUnauthorized = (Boolean) getValue(SSL_REJECT_UNAUTHORIZED, params);
        final Boolean hasUserLogin = null != user && !user.isEmpty();

        final String defaultScheme = sslEnabled ? "https" : "http";
        final Pattern pattern = Pattern.compile("(?<scheme>https?)?(://)?(?<host>[^:]+):?(?<port>\\d+)?");
        final HttpHost[] httpHosts = new HttpHost[hosts.length];
        for (int index=0; index < hosts.length; index++) {
            final Matcher matcher = pattern.matcher(hosts[index].trim());
            if (matcher.find()) {
                final String scheme = matcher.group("scheme") != null ? matcher.group("scheme") : defaultScheme;
                final String host = matcher.group("host");
                final Integer port = matcher.group("port") != null ? Integer.valueOf(matcher.group("port")) : defaultPort;
                httpHosts[index] = new HttpHost(host, port, scheme);
                sslEnabled = sslEnabled || scheme != null && scheme.startsWith("https");
            } else {
                throw new IOException("Unable to parse host");
            }
        }

        final RestClientBuilder builder = RestClient.builder(httpHosts);

        if (sslEnabled || hasUserLogin) {
            builder.setHttpClientConfigCallback(new RestClientBuilder.HttpClientConfigCallback() {
                private CredentialsProvider credentialsProvider = null;
                private Boolean sslEnabled = false;

                private RestClientBuilder.HttpClientConfigCallback init(Boolean sslEnabled){
                    this.sslEnabled = sslEnabled;
                    if (hasUserLogin) {
                        this.credentialsProvider = new BasicCredentialsProvider();
                        this.credentialsProvider.setCredentials(
                                AuthScope.ANY,
                                new UsernamePasswordCredentials(user, passwd)
                        );
                    }
                    return this;
                }

                @Override
                public HttpAsyncClientBuilder customizeHttpClient(HttpAsyncClientBuilder httpClientBuilder) {
                    httpClientBuilder.useSystemProperties();

                    if(this.sslEnabled) {
                        if (!sslRejectUnauthorized) {
                            httpClientBuilder.setSSLHostnameVerifier((host, session) -> true);
                            try {
                                httpClientBuilder.setSSLContext(SSLContextBuilder.create().loadTrustMaterial((chain, authType) -> true).build());
                            } catch (KeyManagementException | NoSuchAlgorithmException | KeyStoreException e) {
                                throw new UncheckedIOException(new IOException("Unable to create SSLContext", e));
                            }
                        }
                    }

                    if(hasUserLogin){
                        httpClientBuilder.setDefaultCredentialsProvider(this.credentialsProvider);
                    }

                    return httpClientBuilder;
                }

            }.init(sslEnabled) );
        }

        return builder.build();
    }

    @Override
    public DataStore createNewDataStore(Map<String, Serializable> params) throws IOException {
        return null;
    }

    private Object getValue(Param param, Map<String, Serializable> params) throws IOException {
        final Object value;
        if (param.lookUp(params) != null) {
            value = param.lookUp(params);
        } else {
            value = param.sample;
        }
        return value;
    }

}
