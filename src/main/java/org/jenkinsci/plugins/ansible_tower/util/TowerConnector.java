package org.jenkinsci.plugins.ansible_tower.util;

import com.google.common.net.HttpHeaders;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.commons.codec.binary.Base64;
import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpEntityEnclosingRequestBase;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpHead;
import org.apache.http.client.methods.HttpPatch;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.ssl.TrustStrategy;
import org.apache.http.util.EntityUtils;
import org.jenkinsci.plugins.ansible_tower.exceptions.AnsibleTowerDoesNotSupportAuthToken;
import org.jenkinsci.plugins.ansible_tower.exceptions.AnsibleTowerException;
import org.jenkinsci.plugins.ansible_tower.exceptions.AnsibleTowerItemDoesNotExist;
import org.jenkinsci.plugins.ansible_tower.exceptions.AnsibleTowerRefusesToGiveToken;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Vector;

public class TowerConnector implements Serializable {
    private static final long serialVersionUID = 1L;
    // If adding a new method, make sure to update getMethodName()
    public static final int GET = 1;
    public static final int POST = 2;
    public static final int PATCH = 3;
    public static final String JOB_TEMPLATE_TYPE = "job";
    public static final String WORKFLOW_TEMPLATE_TYPE = "workflow";
    private static final String ARTIFACTS = "artifacts";
    private static final String API_VERSION = "v2";

    private String authorizationHeader = null;
    private String oauthToken = null;
    private String oAuthTokenID = null;
    private final String url;
    private final String username;
    private final String password;
    private TowerVersion towerVersion = null;
    private final boolean trustAllCerts;
    private boolean importChildWorkflowLogs = false;
    private final TowerLogger logger = new TowerLogger();
    private final HashMap<Long, Long> logIdForWorkflows = new HashMap<>();
    private final HashMap<Long, Long> logIdForJobs = new HashMap<>();

    private boolean removeColor = true;
    private boolean getFullLogs = false;
    private final HashMap<String, String> jenkinsExports = new HashMap<>();

    private transient CloseableHttpClient httpClient;
    private transient PoolingHttpClientConnectionManager connectionManager;

    private final int connectTimeout;
    private final int socketTimeout;
    private final int connectionRequestTimeout;

    private static final int DEFAULT_CONNECT_TIMEOUT_SECONDS = 10;
    private static final int DEFAULT_SOCKET_TIMEOUT_SECONDS = 30;
    private static final int DEFAULT_CONNECTION_REQUEST_TIMEOUT_SECONDS = 10;

    public TowerConnector(String url, String username, String password) { this(url, username, password, null, false, false, null, null, null); }

    public TowerConnector(String url, String username, String password, String oauthToken, Boolean trustAllCerts, Boolean debug, String connectTimeoutStr, String socketTimeoutStr, String requestTimeoutStr) {
        if(url != null && !url.isEmpty() && url.charAt(url.length() - 1) == '/') {
            this.url = url.substring(0, (url.length() - 1));
        } else {
            this.url = url;
        }
        this.username = username;
        this.password = password;
        this.oauthToken = oauthToken;
        this.trustAllCerts = trustAllCerts;

        // Parse timeouts
        this.connectTimeout = parseTimeout(connectTimeoutStr, DEFAULT_CONNECT_TIMEOUT_SECONDS);
        this.socketTimeout = parseTimeout(socketTimeoutStr, DEFAULT_SOCKET_TIMEOUT_SECONDS);
        this.connectionRequestTimeout = parseTimeout(requestTimeoutStr, DEFAULT_CONNECTION_REQUEST_TIMEOUT_SECONDS);

        this.setDebug(debug);
        try {
            this.getVersion();
            if(this.towerVersion != null) {
                logger.logMessage("Connecting to Tower version: " + this.towerVersion.getVersion());
            }
        } catch(AnsibleTowerException ate) {
            logger.logMessage("Failed to get Tower version; auth errors may ensue: "+ ate.getMessage());
        }
        logger.logMessage("Created a connector with "+ username +"@"+ this.url);
    }

    private int parseTimeout(String timeoutStr, int defaultValue) {
        if (timeoutStr != null && !timeoutStr.trim().isEmpty()) {
            try {
                int timeout = Integer.parseInt(timeoutStr.trim());
                if (timeout > 0) {
                    return timeout;
                }
            } catch (NumberFormatException e) {
                logger.logMessage("Invalid timeout value '" + timeoutStr + "', using default of " + defaultValue + "s.");
            }
        }
        return defaultValue;
    }

    public void setDebug(boolean debug) {
        logger.setDebugging(debug);
    }
    public void setRemoveColor(boolean removeColor) { this.removeColor = removeColor;}
    public void setGetWorkflowChildLogs(boolean importChildWorkflowLogs) { this.importChildWorkflowLogs = importChildWorkflowLogs; }
    public void setGetFullLogs(boolean getFullLogs) { this.getFullLogs = getFullLogs; }
    public HashMap<String, String> getJenkinsExports() { return jenkinsExports; }

    private CloseableHttpClient getHttpClient() throws AnsibleTowerException {
        if (this.httpClient == null) {
            try {
                RequestConfig requestConfig = RequestConfig.custom()
                        .setConnectTimeout(this.connectTimeout * 1000)
                        .setSocketTimeout(this.socketTimeout * 1000)
                        .setConnectionRequestTimeout(this.connectionRequestTimeout * 1000)
                        .build();

                HttpClientBuilder clientBuilder = HttpClientBuilder.create()
                        .setDefaultRequestConfig(requestConfig);

                Registry<ConnectionSocketFactory> socketFactoryRegistry;
                if (this.trustAllCerts) {
                    logger.logMessage("Forcing cert trust");
                    TrustStrategy acceptingTrustStrategy = (chain, authType) -> true;
                    SSLContext sslContext = SSLContexts.custom().loadTrustMaterial(null, acceptingTrustStrategy).build();
                    SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslContext, SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
                    socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
                            .register("http", PlainConnectionSocketFactory.getSocketFactory())
                            .register("https", sslsf)
                            .build();
                } else {
                    socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
                            .register("http", PlainConnectionSocketFactory.getSocketFactory())
                            .register("https", SSLConnectionSocketFactory.getSystemSocketFactory())
                            .build();
                }

                this.connectionManager = new PoolingHttpClientConnectionManager(socketFactoryRegistry);
                this.connectionManager.setMaxTotal(100);
                this.connectionManager.setDefaultMaxPerRoute(20);
                this.connectionManager.setValidateAfterInactivity(5000);

                clientBuilder.setConnectionManager(this.connectionManager);
                clientBuilder.setKeepAliveStrategy((response, context) -> 60 * 1000);

                this.httpClient = clientBuilder.build();

            } catch (Exception e) {
                throw new AnsibleTowerException("Failed to create HttpClient: " + e.getMessage(), e);
            }
        }
        return this.httpClient;
    }


    private String buildEndpoint(String endpoint) {
        if(endpoint.startsWith("/api/")) { return endpoint; }

        String full_endpoint = "/api/"+ API_VERSION;
        if(!endpoint.startsWith("/")) { full_endpoint += "/"; }
        full_endpoint += endpoint;
        return full_endpoint;
    }

    private HttpResponse makeRequest(int requestType, String endpoint) throws AnsibleTowerException {
        return makeRequest(requestType, endpoint, null, false);
    }

    private HttpResponse makeRequest(int requestType, String endpoint, JSONObject body) throws AnsibleTowerException {
        return makeRequest(requestType, endpoint, body, false);
    }

    public HttpResponse makeRequest(int requestType, String endpoint, JSONObject body, boolean noAuth) throws AnsibleTowerException {
        URI myURI;
        try {
            myURI = new URI(url + buildEndpoint(endpoint));
        } catch(Exception e) {
            throw new AnsibleTowerException("URL issue: "+ e.getMessage(), e);
        }

        logger.logMessage("Building "+ getMethodName(requestType) +" request to "+ myURI.toString());

        HttpUriRequest request;
        if(requestType == GET) {
            request = new HttpGet(myURI);
        } else if(requestType ==  POST || requestType == PATCH) {
            HttpEntityEnclosingRequestBase myRequest;
            if(requestType == POST) {
                myRequest = new HttpPost(myURI);
            } else {
                myRequest = new HttpPatch(myURI);
            }
            if (body != null && !body.isEmpty()) {
                try {
                    StringEntity bodyEntity = new StringEntity(body.toString(), StandardCharsets.UTF_8);
                    myRequest.setEntity(bodyEntity);
                } catch (Exception uee) {
                    throw new AnsibleTowerException("Unable to encode body as JSON: " + uee.getMessage(), uee);
                }
            }
            request = myRequest;
            request.setHeader("Content-Type", "application/json");
        } else {
            throw new AnsibleTowerException("The requested method is unknown");
        }

        if(!noAuth) {
            if(this.authorizationHeader == null) {
                logger.logMessage("Determining authorization headers");
                if(this.oauthToken != null) {
                    logger.logMessage("Adding oauth bearer token from Jenkins");
                    this.authorizationHeader = "Bearer "+ this.oauthToken;
                } else if(this.username != null && this.password != null) {
                    if (this.towerSupports("/api/o/")) {
                        logger.logMessage("Getting an oAuth token for "+ this.username);
                        try {
                            this.authorizationHeader = "Bearer " + this.getOAuthToken();
                        } catch(AnsibleTowerException ate) {
                            logger.logMessage("Unable to get oAuth Token: "+ ate.getMessage());
                        }
                    }
                    if(this.authorizationHeader == null && this.towerSupports("/api/v2/authtoken")) {
                        logger.logMessage("Getting a legacy token for " + this.username);
                        try {
                            this.authorizationHeader = "Token " + this.getAuthToken();
                        } catch (AnsibleTowerException ate) {
                            logger.logMessage("Unable to get legacy token: " + ate.getMessage());
                        }
                    }
                    if (this.authorizationHeader == null) {
                        logger.logMessage("Reverting to basic auth");
                        this.authorizationHeader = this.getBasicAuthString();
                    }
                } else {
                    throw new AnsibleTowerException("Auth is required for this call but no auth info exists");
                }
            }
            if(this.authorizationHeader == null) {
                throw new AnsibleTowerException("Failed to obtain an authorization header");
            }
            request.setHeader(HttpHeaders.AUTHORIZATION, this.authorizationHeader);
        }

        CloseableHttpClient client = getHttpClient();
        HttpResponse response;
        try {
            response = client.execute(request);
        } catch(Exception e) {
            throw new AnsibleTowerException("Unable to make tower request: "+ e.getMessage(), e);
        }

        logger.logMessage("Request completed with ("+ response.getStatusLine().getStatusCode() +")");
        int statusCode = response.getStatusLine().getStatusCode();

        if(statusCode == 404) {
            EntityUtils.consumeQuietly(response.getEntity());
            throw new AnsibleTowerItemDoesNotExist("The item does not exist");
        } else if(statusCode == 401) {
            EntityUtils.consumeQuietly(response.getEntity());
            throw new AnsibleTowerException("Username/password invalid");
        } else if(statusCode == 403) {
            String exceptionText = "Request was forbidden";
            try {
                String json = EntityUtils.toString(response.getEntity());
                logger.logMessage(json);
                JSONObject responseObject = JSONObject.fromObject(json);
                if(responseObject.containsKey("detail")) {
                    exceptionText += ": "+ responseObject.getString("detail");
                }
            } catch (Exception e) {
                logger.logMessage("Unable to parse 403 response body: " + e.getMessage());
            } finally {
                EntityUtils.consumeQuietly(response.getEntity());
            }
            throw new AnsibleTowerException(exceptionText);
        }
        return response;
    }

    private boolean towerSupports(String end_point) throws AnsibleTowerException {
        URI myURI;
        try {
            myURI = new URI(url + end_point);
        } catch(Exception e) {
            throw new AnsibleTowerException("Unable to construct URL for "+ end_point +": "+ e.getMessage(), e);
        }
        logger.logMessage("Checking if Tower supports: "+ myURI.toString());
        HttpHead request = new HttpHead(myURI);
        try {
            HttpResponse response = getHttpClient().execute(request);
            EntityUtils.consumeQuietly(response.getEntity());
            int statusCode = response.getStatusLine().getStatusCode();
            logger.logMessage("Support check request completed with ("+ statusCode +")");
            return statusCode != 404;
        } catch(Exception e) {
            throw new AnsibleTowerException("Unable to make Tower HEAD request for "+ end_point +": "+ e.getMessage(), e);
        }
    }

    public String getURL() { return url; }

    public void getVersion() throws AnsibleTowerException {
        HttpResponse response = makeRequest(GET, "ping/", null, true);
        try {
            if(response.getStatusLine().getStatusCode() != 200) {
                throw new AnsibleTowerException("Unexpected error code from ping ("+ response.getStatusLine().getStatusCode() +")");
            }
            logger.logMessage("Ping page loaded");
            String json = EntityUtils.toString(response.getEntity());
            JSONObject responseObject = JSONObject.fromObject(json);
            if (responseObject.containsKey("version")) {
                logger.logMessage("Successfully got version "+ responseObject.getString("version"));
                this.towerVersion = new TowerVersion(responseObject.getString("version"));
            }
        } catch (IOException e) {
            throw new AnsibleTowerException("Unable to read ping response: " + e.getMessage(), e);
        } finally {
            EntityUtils.consumeQuietly(response.getEntity());
        }
    }

    public void testConnection() throws AnsibleTowerException {
        if(url == null) { throw new AnsibleTowerException("The URL is undefined"); }
        logger.logMessage("Testing authentication");
        HttpResponse response = makeRequest(GET, "jobs/");
        try {
            if(response.getStatusLine().getStatusCode() != 200) {
                throw new AnsibleTowerException("Failed to get authenticated connection ("+ response.getStatusLine().getStatusCode() +")");
            }
        } finally {
            EntityUtils.consumeQuietly(response.getEntity());
        }
        releaseToken();
    }

    public String convertPotentialStringToID(String idToCheck, String api_endpoint) throws AnsibleTowerException {
        JSONObject foundItem = rawLookupByString(idToCheck, api_endpoint);
        logger.logMessage("Response from lookup: "+ foundItem.getString("id"));
        return foundItem.getString("id");
    }

    public JSONObject rawLookupByString(String idToCheck, String api_endpoint) throws AnsibleTowerException {
        try {
            Integer.parseInt(idToCheck);
            HttpResponse response = makeRequest(GET, api_endpoint + idToCheck +"/");
            try {
                String json = EntityUtils.toString(response.getEntity());
                JSONObject responseObject = JSONObject.fromObject(json);
                if(!responseObject.containsKey("id")) {
                    throw new AnsibleTowerItemDoesNotExist("Did not get an ID back from the request");
                }
                return responseObject;
            } catch (IOException ioe) {
                throw new AnsibleTowerException(ioe.getMessage(), ioe);
            } finally {
                EntityUtils.consumeQuietly(response.getEntity());
            }
        } catch(NumberFormatException nfe) {
            HttpResponse response;
            try {
                response = makeRequest(GET, api_endpoint + "?name=" + URLEncoder.encode(idToCheck, "UTF-8"));
            } catch(UnsupportedEncodingException e) {
                throw new AnsibleTowerException("Unable to encode item name for lookup", e);
            }

            try {
                JSONObject responseObject = JSONObject.fromObject(EntityUtils.toString(response.getEntity()));
                if(!responseObject.containsKey("results")) {
                    throw new AnsibleTowerException("Response for items does not contain results");
                }
                if(responseObject.getInt("count") == 0) {
                    throw new AnsibleTowerItemDoesNotExist("Unable to get any results when looking up "+ idToCheck);
                } else if(responseObject.getInt("count") > 1) {
                    throw new AnsibleTowerException("The item "+ idToCheck +" is not unique");
                } else {
                    return (JSONObject) responseObject.getJSONArray("results").get(0);
                }
            } catch (IOException ioe) {
                throw new AnsibleTowerException("Unable to convert response for all items into json: " + ioe.getMessage(), ioe);
            } finally {
                EntityUtils.consumeQuietly(response.getEntity());
            }
        }
    }

    public JSONObject getJobTemplate(String jobTemplate, String templateType) throws AnsibleTowerException {
        if(jobTemplate == null || jobTemplate.isEmpty()) {
            throw new AnsibleTowerException("Template can not be null");
        }

        checkTemplateType(templateType);
        String apiEndPoint = templateType.equalsIgnoreCase(WORKFLOW_TEMPLATE_TYPE) ? "/workflow_job_templates/" : "/job_templates/";

        String templateId;
        try {
            templateId = convertPotentialStringToID(jobTemplate, apiEndPoint);
        } catch(AnsibleTowerItemDoesNotExist atidne) {
            String ucTemplateType = templateType.substring(0, 1).toUpperCase() + templateType.substring(1);
            throw new AnsibleTowerException(ucTemplateType +" template '"+ jobTemplate +"' does not exist in tower", atidne);
        } catch(AnsibleTowerException ate) {
            throw new AnsibleTowerException("Unable to find "+ templateType +" template '"+ jobTemplate +"': "+ ate.getMessage(), ate);
        }

        HttpResponse response = makeRequest(GET, apiEndPoint + templateId + "/");
        try {
            if (response.getStatusLine().getStatusCode() != 200) {
                throw new AnsibleTowerException("Unexpected error code returned when getting template (" + response.getStatusLine().getStatusCode() + ")");
            }
            return JSONObject.fromObject(EntityUtils.toString(response.getEntity()));
        } catch (IOException e) {
            throw new AnsibleTowerException("Unable to read template response and convert it into json: " + e.getMessage(), e);
        } finally {
            EntityUtils.consumeQuietly(response.getEntity());
        }
    }

    private void processCredentials(String credential, JSONObject postBody) throws AnsibleTowerException {
        HttpResponse response = makeRequest(GET,"/credential_types/?or__kind=ssh&or__kind=vault");
        JSONObject responseObject;
        try {
            if(response.getStatusLine().getStatusCode() != 200) {
                throw new AnsibleTowerException("Unable to lookup the credential types ("+ response.getStatusLine().getStatusCode() +")");
            }
            responseObject = JSONObject.fromObject(EntityUtils.toString(response.getEntity()));
        } catch(IOException ioe) {
            throw new AnsibleTowerException("Unable to read credential types response and convert it into json: "+ ioe.getMessage(), ioe);
        } finally {
            EntityUtils.consumeQuietly(response.getEntity());
        }

        if(responseObject.getInt("count") < 2) {
            logger.logMessage("[WARNING]: Unable to find both machine and vault credential types. This may be normal for older Tower versions.");
        }

        long machine_credential_type = -1L;
        long vault_credential_type = -1L;
        JSONArray credentialTypesArray = responseObject.getJSONArray("results");
        for(Object credTypeObj : credentialTypesArray) {
            JSONObject aCredentialType = (JSONObject) credTypeObj;
            if(aCredentialType.getString("kind").equalsIgnoreCase("ssh")) {
                machine_credential_type = aCredentialType.getLong("id");
            } else if(aCredentialType.getString("kind").equalsIgnoreCase("vault")) {
                vault_credential_type = aCredentialType.getLong("id");
            }
        }

        HashMap<String, Vector<Long>> credentials = new HashMap<>();
        credentials.put("vault", new Vector<>());
        credentials.put("machine", new Vector<>());
        credentials.put("extra", new Vector<>());
        for(String credentialString : credential.split(","))  {
            try {
                JSONObject jsonCredential = rawLookupByString(credentialString.trim(), "/credentials/");
                String myCredentialType;
                int credentialTypeId = jsonCredential.getInt("credential_type");
                if (credentialTypeId == machine_credential_type) {
                    myCredentialType = "machine";
                } else if (credentialTypeId == vault_credential_type) {
                    myCredentialType = "vault";
                } else {
                    myCredentialType = "extra";
                }
                credentials.get(myCredentialType).add(jsonCredential.getLong("id"));
            } catch(AnsibleTowerException ate) {
                throw new AnsibleTowerException("Unable to find credential "+ credentialString.trim() +": "+ ate.getMessage(), ate);
            }
        }

        if( this.towerVersion != null && this.towerVersion.is_greater_or_equal("3.5.0") || (credentials.get("machine").size() > 1 || credentials.get("vault").size() > 1) ) {
            JSONArray allCredentials = new JSONArray();
            allCredentials.addAll(credentials.get("machine"));
            allCredentials.addAll(credentials.get("vault"));
            allCredentials.addAll(credentials.get("extra"));
            postBody.put("credentials", allCredentials);
        } else {
            if(!credentials.get("machine").isEmpty()) { postBody.put("credential", credentials.get("machine").get(0)); }
            if(!credentials.get("vault").isEmpty()) { postBody.put("vault_credential", credentials.get("vault").get(0)); }
            if(!credentials.get("extra").isEmpty()) {
                JSONArray extraCredentials = new JSONArray();
                extraCredentials.addAll(credentials.get("extra"));
                postBody.put("extra_credentials", extraCredentials);
            }
        }
    }

    public long submitTemplate(long jobTemplateId, String extraVars, String limit, String jobTags, String skipJobTags, String jobType, String inventory, String credential, String scmBranch, String templateType) throws AnsibleTowerException {
        checkTemplateType(templateType);
        String apiEndPoint = templateType.equalsIgnoreCase(WORKFLOW_TEMPLATE_TYPE) ? "/workflow_job_templates/" : "/job_templates/";
        JSONObject postBody = new JSONObject();

        if(inventory != null && !inventory.isEmpty()) {
            postBody.put("inventory", convertPotentialStringToID(inventory, "/inventories/"));
        }
        if(credential != null && !credential.isEmpty()) {
            processCredentials(credential, postBody);
        }
        if(limit != null && !limit.isEmpty()) {
            postBody.put("limit", limit);
        }
        if(jobTags != null && !jobTags.isEmpty()) {
            postBody.put("job_tags", jobTags);
        }
        if(skipJobTags != null && !skipJobTags.isEmpty()) {
            postBody.put("skip_tags", skipJobTags);
        }
        if(jobType != null &&  !jobType.isEmpty()){
            postBody.put("job_type", jobType);
        }
        if(extraVars != null && !extraVars.isEmpty()) {
            postBody.put("extra_vars", extraVars);
        }
        if(scmBranch != null && !scmBranch.isEmpty()) {
            postBody.put("scm_branch", scmBranch);
        }

        HttpResponse response = makeRequest(POST, apiEndPoint + jobTemplateId + "/launch/", postBody);
        try {
            if (response.getStatusLine().getStatusCode() == 201) {
                String json = EntityUtils.toString(response.getEntity());
                JSONObject responseObject = JSONObject.fromObject(json);
                if (responseObject.containsKey("id")) {
                    return responseObject.getLong("id");
                }
                logger.logMessage(json);
                throw new AnsibleTowerException("Did not get an ID from the request.");
            } else if (response.getStatusLine().getStatusCode() == 400) {
                String json = EntityUtils.toString(response.getEntity());
                try {
                    JSONObject responseObject = JSONObject.fromObject(json);
                    if(responseObject.containsKey("extra_vars")) {
                        throw new AnsibleTowerException("Extra vars are bad: "+ responseObject.getJSONArray("extra_vars").join(", "));
                    }
                } catch(Exception e) {
                    // Ignore if parsing fails, throw with full body
                }
                throw new AnsibleTowerException("Tower received a bad request (400 response code)\n" + json);
            } else {
                throw new AnsibleTowerException("Unexpected error code returned ("+ response.getStatusLine().getStatusCode() +")");
            }
        } catch(IOException e) {
            throw new AnsibleTowerException("Failed to read response entity: " + e.getMessage(), e);
        } finally {
            EntityUtils.consumeQuietly(response.getEntity());
        }
    }

    public void checkTemplateType(String templateType) throws AnsibleTowerException {
        if(templateType.equalsIgnoreCase(JOB_TEMPLATE_TYPE) || templateType.equalsIgnoreCase(WORKFLOW_TEMPLATE_TYPE)) {
            return;
        }
        throw new AnsibleTowerException("Template type can only be '"+ JOB_TEMPLATE_TYPE +"' or '"+ WORKFLOW_TEMPLATE_TYPE+"'");
    }

    public boolean isJobCompleted(long jobID, String templateType) throws AnsibleTowerException {
        checkTemplateType(templateType);
        String apiEndpoint = templateType.equalsIgnoreCase(WORKFLOW_TEMPLATE_TYPE) ? "/workflow_jobs/" : "/jobs/";
        HttpResponse response = makeRequest(GET, apiEndpoint + jobID + "/");
        try {
            if (response.getStatusLine().getStatusCode() == 200) {
                String json = EntityUtils.toString(response.getEntity());
                JSONObject responseObject = JSONObject.fromObject(json);
                if (responseObject.containsKey("finished")) {
                    String finished = responseObject.getString("finished");
                    if (finished == null || finished.equalsIgnoreCase("null")) {
                        return false;
                    } else {
                        if (responseObject.containsKey(ARTIFACTS)) {
                            logger.logMessage("Processing artifacts");
                            JSONObject artifacts = responseObject.getJSONObject(ARTIFACTS);
                            if (artifacts.containsKey("JENKINS_EXPORT")) {
                                JSONArray exportVariables = artifacts.getJSONArray("JENKINS_EXPORT");
                                for (Object o : exportVariables) {
                                    JSONObject entry = (JSONObject) o;
                                    for (Object key : entry.keySet()) {
                                        jenkinsExports.put(key.toString(), entry.getString(key.toString()));
                                    }
                                }
                            }
                        }
                        return true;
                    }
                }
                logger.logMessage(json);
                throw new AnsibleTowerException("Did not get a finished status from the request.");
            } else {
                throw new AnsibleTowerException("Unexpected error code returned (" + response.getStatusLine().getStatusCode() + ")");
            }
        } catch (IOException e) {
            throw new AnsibleTowerException("Failed to read response entity: " + e.getMessage(), e);
        } finally {
            EntityUtils.consumeQuietly(response.getEntity());
        }
    }

    public void cancelJob(long jobID, String templateType) throws AnsibleTowerException {
        checkTemplateType(templateType);
        String apiEndpoint = (templateType.equalsIgnoreCase(WORKFLOW_TEMPLATE_TYPE) ? "/workflow_jobs/" : "/jobs/") + jobID +"/cancel/";

        // Check if job can be canceled
        HttpResponse getResponse = makeRequest(GET, apiEndpoint);
        try {
            if (getResponse.getStatusLine().getStatusCode() != 200) {
                throw new AnsibleTowerException("Unexpected error code when checking cancel status (" + getResponse.getStatusLine().getStatusCode() + ")");
            }
            JSONObject responseObject = JSONObject.fromObject(EntityUtils.toString(getResponse.getEntity()));
            if(responseObject.containsKey("can_cancel") && !responseObject.getBoolean("can_cancel")) {
                throw new AnsibleTowerException("The job cannot be canceled at this time (it may have already finished).");
            }
        } catch(IOException e) {
            throw new AnsibleTowerException("Failed to read cancel check response", e);
        } finally {
            EntityUtils.consumeQuietly(getResponse.getEntity());
        }

        // Request cancellation
        HttpResponse postResponse = makeRequest(POST, apiEndpoint);
        try {
            if (postResponse.getStatusLine().getStatusCode() != 202) {
                throw new AnsibleTowerException("Unexpected error code when canceling job (" + postResponse.getStatusLine().getStatusCode() + ")");
            }
            logger.logMessage("Cancel request sent successfully.");
        } finally {
            EntityUtils.consumeQuietly(postResponse.getEntity());
        }
    }

    public Vector<String> getLogEvents(long jobID, String templateType) throws AnsibleTowerException {
        checkTemplateType(templateType);
        if(templateType.equalsIgnoreCase(JOB_TEMPLATE_TYPE)) {
            return logJobEvents(jobID);
        } else if(templateType.equalsIgnoreCase(WORKFLOW_TEMPLATE_TYPE)){
            return logWorkflowEvents(jobID);
        }
        throw new AnsibleTowerException("Tower Connector does not know how to log events for a "+ templateType);
    }

    private Vector<String> logJobEvents(long jobID) throws AnsibleTowerException {
        Vector<String> events = new Vector<>();
        long lastLogId = this.logIdForJobs.getOrDefault(jobID, 0L);
        boolean keepChecking = true;
        while(keepChecking) {
            String apiUrl = "/jobs/" + jobID + "/job_events/?order_by=id&id__gt=" + lastLogId;
            HttpResponse response = makeRequest(GET, apiUrl);
            try {
                if (response.getStatusLine().getStatusCode() != 200) {
                    throw new AnsibleTowerException("Unexpected error retrieving job events (" + response.getStatusLine().getStatusCode() + ")");
                }
                String json = EntityUtils.toString(response.getEntity());
                JSONObject responseObject = JSONObject.fromObject(json);

                if(responseObject.containsKey("next") && (responseObject.getString("next") == null || responseObject.getString("next").equalsIgnoreCase("null"))) {
                    keepChecking = false;
                }

                if (responseObject.containsKey("results")) {
                    for (Object anEvent : responseObject.getJSONArray("results")) {
                        JSONObject eventObject = (JSONObject) anEvent;
                        long eventId = eventObject.getLong("id");
                        String stdOut = eventObject.getString("stdout");
                        events.addAll(logLine(stdOut));
                        lastLogId = Math.max(lastLogId, eventId);
                    }
                }
                this.logIdForJobs.put(jobID, lastLogId);
            } catch (IOException e) {
                throw new AnsibleTowerException("Failed to read job events response: " + e.getMessage(), e);
            } finally {
                EntityUtils.consumeQuietly(response.getEntity());
            }
        }
        return events;
    }

    private Vector<String> logWorkflowEvents(long jobID) throws AnsibleTowerException {
        logger.logMessage("Note: Workflow log retrieval is a simplified implementation.");
        Vector<String> events = new Vector<>();
        long lastNodeId = this.logIdForWorkflows.getOrDefault(jobID, 0L);

        String apiUrl = "/workflow_jobs/" + jobID + "/workflow_nodes/?order_by=id&id__gt=" + lastNodeId;
        HttpResponse response = makeRequest(GET, apiUrl);
        try {
            if (response.getStatusLine().getStatusCode() != 200) {
                throw new AnsibleTowerException("Unexpected error retrieving workflow nodes (" + response.getStatusLine().getStatusCode() + ")");
            }
            String json = EntityUtils.toString(response.getEntity());
            JSONObject responseObject = JSONObject.fromObject(json);
            if (responseObject.containsKey("results")) {
                for (Object anEvent : responseObject.getJSONArray("results")) {
                    JSONObject anEventObject = (JSONObject) anEvent;
                    long nodeId = anEventObject.getLong("id");
                    if (anEventObject.containsKey("summary_fields") && anEventObject.getJSONObject("summary_fields").containsKey("job")) {
                        JSONObject job = anEventObject.getJSONObject("summary_fields").getJSONObject("job");
                        String name = job.getString("name");
                        String status = job.getString("status");
                        long childJobId = job.getLong("id");
                        events.addAll(logLine(name + " => " + status + " " + this.getJobURL(childJobId, JOB_TEMPLATE_TYPE)));

                        if(importChildWorkflowLogs) {
                            events.addAll(logJobEvents(childJobId));
                            events.add(""); // Add spacer
                        }
                    }
                    lastNodeId = Math.max(lastNodeId, nodeId);
                }
            }
            this.logIdForWorkflows.put(jobID, lastNodeId);
        } catch(IOException e) {
            throw new AnsibleTowerException("Failed to read workflow nodes response: " + e.getMessage(), e);
        } finally {
            EntityUtils.consumeQuietly(response.getEntity());
        }
        return events;
    }

    public Vector<String> logLine(String output) {
        Vector<String> return_lines = new Vector<>();
        String[] lines = output.split("\\r?\\n");
        for(String line : lines) {
            if(line.contains("JENKINS_EXPORT")) {
                String[] entities = removeColor(line).split("=", 2);
                if(entities.length == 2) {
                    String key = entities[0].replaceAll(".*JENKINS_EXPORT", "").trim();
                    String value = entities[1].replaceAll("^\"|\"$", "").trim();
                    jenkinsExports.put(key, value);
                }
            }
            if(removeColor) {
                line = removeColor(line);
            }
            return_lines.add(line);
        }
        return return_lines;
    }

    private String removeColor(String coloredLine) {
        return coloredLine.replaceAll("\u001B\\[[;\\d]*m", "");
    }

    public boolean isJobFailed(long jobID, String templateType) throws AnsibleTowerException {
        checkTemplateType(templateType);
        String apiEndPoint = templateType.equalsIgnoreCase(WORKFLOW_TEMPLATE_TYPE) ? "/workflow_jobs/" : "/jobs/";
        HttpResponse response = makeRequest(GET, apiEndPoint + jobID + "/");
        try {
            if (response.getStatusLine().getStatusCode() == 200) {
                String json = EntityUtils.toString(response.getEntity());
                JSONObject responseObject = JSONObject.fromObject(json);
                if (responseObject.containsKey("failed")) {
                    return responseObject.getBoolean("failed");
                }
                logger.logMessage(json);
                throw new AnsibleTowerException("Did not get a failed status from the request.");
            } else {
                throw new AnsibleTowerException("Unexpected error code returned (" + response.getStatusLine().getStatusCode() + ")");
            }
        } catch (IOException e) {
            throw new AnsibleTowerException("Failed to read response entity: " + e.getMessage(), e);
        } finally {
            EntityUtils.consumeQuietly(response.getEntity());
        }
    }

    public String getJobURL(long myJobID, String templateType) {
        String path = templateType.equalsIgnoreCase(JOB_TEMPLATE_TYPE) ? "jobs/playbook/" : "workflows/";
        return url +"/#/"+ path + myJobID;
    }

    private String getBasicAuthString() {
        String auth = this.username + ":" + this.password;
        byte[] encodedAuth = Base64.encodeBase64(auth.getBytes(StandardCharsets.UTF_8));
        return "Basic " + new String(encodedAuth, StandardCharsets.UTF_8);
    }

    private String getOAuthToken() throws AnsibleTowerException {
        String tokenURI = url + this.buildEndpoint("/tokens/");
        HttpPost oauthTokenRequest = new HttpPost(tokenURI);
        oauthTokenRequest.setHeader(HttpHeaders.AUTHORIZATION, this.getBasicAuthString());
        JSONObject body = new JSONObject();
        body.put("description", "Jenkins Token");
        body.put("application", (Object) null);
        body.put("scope", "write");
        try {
            oauthTokenRequest.setEntity(new StringEntity(body.toString(), StandardCharsets.UTF_8));
        } catch(Exception uee) {
            throw new AnsibleTowerException("Unable to encode body as JSON: "+ uee.getMessage(), uee);
        }
        oauthTokenRequest.setHeader("Content-Type", "application/json");

        HttpResponse response = null;
        try {
            logger.logMessage("Calling for oauth token at "+ tokenURI);
            response = getHttpClient().execute(oauthTokenRequest);
            int statusCode = response.getStatusLine().getStatusCode();
            if(statusCode == 400 || statusCode == 401) {
                throw new AnsibleTowerException("Username/password invalid");
            } else if(statusCode == 404) {
                throw new AnsibleTowerDoesNotSupportAuthToken("Server does not have tokens endpoint: " + tokenURI);
            } else if(statusCode == 403) {
                throw new AnsibleTowerRefusesToGiveToken("Server refuses to give tokens");
            } else if(statusCode != 200 && statusCode != 201) {
                throw new AnsibleTowerException("Unable to get oauth token, server responded with ("+ statusCode +")");
            }
            String json = EntityUtils.toString(response.getEntity());
            JSONObject responseObject = JSONObject.fromObject(json);
            if (responseObject.containsKey("id")) {
                this.oAuthTokenID = responseObject.getString("id");
            }
            if (responseObject.containsKey("token")) {
                logger.logMessage("AuthToken acquired ("+ this.oAuthTokenID +")");
                return responseObject.getString("token");
            }
            logger.logMessage(json);
            throw new AnsibleTowerException("Did not get an oauth token from the request.");
        } catch(Exception e) {
            throw new AnsibleTowerException("Unable to make request for an oauth token: "+ e.getMessage(), e);
        } finally {
            if(response != null) {
                EntityUtils.consumeQuietly(response.getEntity());
            }
        }
    }

    private String getAuthToken() throws AnsibleTowerException {
        logger.logMessage("Getting auth token for "+ this.username);
        String tokenURI = url + this.buildEndpoint("/authtoken/");
        HttpPost tokenRequest = new HttpPost(tokenURI);
        tokenRequest.setHeader(HttpHeaders.AUTHORIZATION, this.getBasicAuthString());
        JSONObject body = new JSONObject();
        body.put("username", this.username);
        body.put("password", this.password);
        try {
            tokenRequest.setEntity(new StringEntity(body.toString(), StandardCharsets.UTF_8));
        } catch(Exception uee) {
            throw new AnsibleTowerException("Unable to encode body as JSON: "+ uee.getMessage(), uee);
        }
        tokenRequest.setHeader("Content-Type", "application/json");
        HttpResponse response = null;
        try {
            logger.logMessage("Calling for token at "+ tokenURI);
            response = getHttpClient().execute(tokenRequest);
            int statusCode = response.getStatusLine().getStatusCode();
            if(statusCode == 400) {
                throw new AnsibleTowerException("Username/password invalid");
            } else if(statusCode == 404) {
                throw new AnsibleTowerDoesNotSupportAuthToken("Server does not have endpoint: " + tokenURI);
            } else if(statusCode != 200 && statusCode != 201) {
                throw new AnsibleTowerException("Unable to get auth token, server responded with ("+ statusCode +")");
            }
            String json = EntityUtils.toString(response.getEntity());
            JSONObject responseObject = JSONObject.fromObject(json);
            if (responseObject.containsKey("token")) {
                logger.logMessage("AuthToken acquired");
                return responseObject.getString("token");
            }
            logger.logMessage(json);
            throw new AnsibleTowerException("Did not get a token from the request.");
        } catch(Exception e) {
            throw new AnsibleTowerException("Unable to make request for an authtoken: "+ e.getMessage(), e);
        } finally {
            if(response != null) {
                EntityUtils.consumeQuietly(response.getEntity());
            }
        }
    }

    public void releaseToken() {
        if(this.oAuthTokenID != null) {
            logger.logMessage("Deleting oAuth token "+ this.oAuthTokenID +" for " + this.username);
            try {
                String tokenURI = url + this.buildEndpoint("/tokens/" + this.oAuthTokenID + "/");
                HttpDelete tokenRequest = new HttpDelete(tokenURI);
                tokenRequest.setHeader(HttpHeaders.AUTHORIZATION, this.getBasicAuthString());

                HttpResponse response = getHttpClient().execute(tokenRequest);
                EntityUtils.consumeQuietly(response.getEntity());

                if(response.getStatusLine().getStatusCode() == 400) {
                    logger.logMessage("Unable to delete oAuthToken: Invalid Authorization");
                } else if(response.getStatusLine().getStatusCode() != 204) {
                    logger.logMessage("Unable to delete oauth token, server responded with ("+ response.getStatusLine().getStatusCode() +")");
                } else {
                    logger.logMessage("oAuth Token deleted");
                }
            } catch(Exception e) {
                logger.logMessage("Failed to delete token: "+ e.getMessage());
            } finally {
                this.oAuthTokenID = null;
                this.authorizationHeader = null;
            }
        }

        if (this.httpClient != null) {
            try {
                this.httpClient.close();
            } catch (IOException e) {
                logger.logMessage("Error closing HttpClient: " + e.getMessage());
            }
        }
        if (this.connectionManager != null) {
            this.connectionManager.close();
        }
    }

    public String getMethodName(int methodId) {
        switch (methodId) {
            case 1: return "GET";
            case 2: return "POST";
            case 3: return "PATCH";
            default: return "UNKNOWN";
        }
    }
}