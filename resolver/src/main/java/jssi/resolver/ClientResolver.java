/*
 *  Copyright 2013 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package jssi.resolver;

import io.reactivex.Observable;
import org.apache.http.HttpEntity;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uniresolver.ResolutionException;
import uniresolver.UniResolver;
import uniresolver.result.ResolveResult;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.util.Map;
import java.util.concurrent.Callable;

public class ClientResolver implements UniResolver {

    private static Logger LOG = LoggerFactory.getLogger(ClientResolver.class);

    public static final HttpClient DEFAULT_HTTP_CLIENT = HttpClients.createDefault();
    public static final URI DEFAULT_RESOLVER_URI = URI.create("http://localhost:8080/resolver/1.0/identifiers/");
    public static final URI DEFAULT_PROPERTIES_URI = URI.create("http://localhost:8080/resolver/1.0/properties");

    private HttpClient httpClient = DEFAULT_HTTP_CLIENT;
    private URI resolverUri = DEFAULT_RESOLVER_URI;
    private URI propertiesUri = DEFAULT_PROPERTIES_URI;

    public ClientResolver() {
    }

    @Override
    public Observable<ResolveResult> resolve(String identifier) throws ResolutionException {
        return resolve(identifier, null);
    }

    @Override
    public Observable<ResolveResult> resolve(final String identifier, Map<String, String> options) throws ResolutionException {
        if (identifier == null) {
            throw new NullPointerException();
        }

        // encode identifier
        String encodedIdentifier;

        try {
            encodedIdentifier = URLEncoder.encode(identifier, "UTF-8");
        } catch (UnsupportedEncodingException ex) {
            throw new ResolutionException(ex.getMessage(), ex);
        }

        // prepare HTTP request
        String uri = resolverUri.toString();
        if (!uri.endsWith("/")) {
            uri += "/";
            uri += encodedIdentifier;
        }

        final String uriString = uri + encodedIdentifier;

        HttpGet request = new HttpGet(URI.create(uriString));

        return Observable.fromCallable(new Callable<ResolveResult>() {

            @Override
            public ResolveResult call() throws ResolutionException {
                ResolveResult resolveResult;

                LOG.debug(String.format("Request for identifier %s to: %s", identifier, uriString));

                try (CloseableHttpResponse httpResponse = (CloseableHttpResponse) httpClient.execute(request)) {

                    int statusCode = httpResponse.getStatusLine().getStatusCode();
                    String statusMessage = httpResponse.getStatusLine().getReasonPhrase();

                    LOG.debug(String.format("Response status from %s: %d %s", uriString, statusCode, statusMessage));

                    if (statusCode == 404){
                        return null;
                    }

                    HttpEntity httpEntity = httpResponse.getEntity();
                    String httpBody = EntityUtils.toString(httpEntity);
                    EntityUtils.consume(httpEntity);

                    LOG.debug(String.format("Response body from %s: %s", uriString, httpBody));

                    if (httpResponse.getStatusLine().getStatusCode() > 200) {
                        LOG.warn(String.format("Cannot retrieve RESOLVE RESULT for %s from &s: %s", identifier, uriString, httpBody));
                        throw new ResolutionException(httpBody);
                    }

                    resolveResult = ResolveResult.fromJson(httpBody);
                } catch (IOException ex) {
                    throw new ResolutionException(String.format("Cannot retrieve RESOLVE RESULT for %s from %s: %s", identifier, uriString, ex.getMessage()), ex);
                }

                LOG.debug(String.format("Retrieved RESOLVE RESULT for %s (%s) %s", identifier, uriString, resolveResult));
                // done
                return resolveResult;
            }
        });
    }

    @Override
    public Map<String, Map<String, Object>> properties() throws ResolutionException {
        return null;
    }

    public void setResolverUri(URI resolverUri) {
        this.resolverUri = resolverUri;
    }
}
