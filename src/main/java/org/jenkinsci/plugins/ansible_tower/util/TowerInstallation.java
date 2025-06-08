package org.jenkinsci.plugins.ansible_tower.util;

/*
    This class represents a Tower installation
 */

import static com.cloudbees.plugins.credentials.CredentialsMatchers.instanceOf;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.common.UsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.model.Run;
import jenkins.model.Jenkins;
import org.jenkinsci.plugins.plaincredentials.StringCredentials;
import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.model.Project;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardUsernameCredentials;
import org.kohsuke.stapler.verb.POST;

import java.util.List;

public class TowerInstallation extends AbstractDescribableImpl<TowerInstallation> {
    private static final long getSerialVersionUID = 1L;

    private final String towerDisplayName;
    private final String towerURL;
    private String towerCredentialsId;
    private final boolean towerTrustCert;
    private final boolean enableDebugging;
    private final String connectTimeout;
    private final String socketTimeout;
    private final String connectionRequestTimeout;
    private Run run;

    @DataBoundConstructor
    public TowerInstallation(String towerDisplayName, String towerURL, String towerCredentialsId, boolean towerTrustCert, boolean enableDebugging, String connectTimeout, String socketTimeout, String connectionRequestTimeout) {
        this.towerDisplayName = towerDisplayName;
        this.towerCredentialsId = towerCredentialsId;
        this.towerURL = towerURL;
        this.towerTrustCert = towerTrustCert;
        this.enableDebugging = enableDebugging;
        this.connectTimeout = connectTimeout;
        this.socketTimeout = socketTimeout;
        this.connectionRequestTimeout = connectionRequestTimeout;
    }

    public String getTowerDisplayName() {
        return this.towerDisplayName;
    }

    public String getTowerURL() {
        return this.towerURL;
    }

    public String getTowerCredentialsId() {
        return this.towerCredentialsId;
    }

    public boolean getTowerTrustCert() {
        return this.towerTrustCert;
    }

    public boolean getEnableDebugging() {
        return this.enableDebugging;
    }

    public String getConnectTimeout() { return connectTimeout; }

    public String getSocketTimeout() { return socketTimeout; }

    public String getConnectionRequestTimeout() { return connectionRequestTimeout; }

    public void setTowerCredentialsId(String towerCredentialsId) {
        this.towerCredentialsId = towerCredentialsId;
    }

    public void setRun(Run run) {
        this.run = run;
    }

    public TowerConnector getTowerConnector() {
        return TowerInstallation.getTowerConnectorStatic(this.towerURL, this.towerCredentialsId, this.towerTrustCert,
                this.enableDebugging, this.run, this.connectTimeout, this.socketTimeout, this.connectionRequestTimeout);
    }

    public static TowerConnector getTowerConnectorStatic(String towerURL, String towerCredentialsId, boolean trustCert,
                                                         boolean enableDebugging, Run run,
                                                         String connectTimeout, String socketTimeout, String connectionRequestTimeout) {
        String username = null;
        String password = null;
        String oauth_token = null;
        if (StringUtils.isNotBlank(towerCredentialsId)) {
            List<StandardUsernamePasswordCredentials> credsList = getCredsList(StandardUsernamePasswordCredentials.class, run);
            for (StandardUsernamePasswordCredentials creds : credsList) {
                if (creds.getId().equals(towerCredentialsId)) {
                    username = creds.getUsername();
                    password = creds.getPassword().getPlainText();
                }
            }
            List<StringCredentials> secretList = getCredsList(StringCredentials.class, run);
            for (StringCredentials secret : secretList) {
                if (secret.getId().equals(towerCredentialsId)) {
                    oauth_token = secret.getSecret().getPlainText();
                }
            }
        }
        TowerConnector testConnector = new TowerConnector(towerURL, username, password, oauth_token, trustCert, enableDebugging, connectTimeout, socketTimeout, connectionRequestTimeout);
        return testConnector;
    }
    
    @SuppressFBWarnings("DCN_NULLPOINTER_EXCEPTION")
    private static <C extends Credentials> List<C> getCredsList(Class<C> type, Run run) {
        List<C> credsList;

        if (run != null && run.getParent() != null) {
            credsList = CredentialsProvider.lookupCredentials(type,
                    run.getParent(), null, new DomainRequirement());
        } else {
            credsList = CredentialsProvider.lookupCredentials(type);
        }

        return credsList;
    }

    @Extension
    public static class TowerInstallationDescriptor extends Descriptor<TowerInstallation> {

        private FormValidation doCheckTimeoutField(String value, String fieldName) {
            if (StringUtils.isBlank(value)) {
                return FormValidation.ok("Default will be used.");
            }
            try {
                if (Integer.parseInt(value) > 0) {
                    return FormValidation.ok();
                }
            } catch (NumberFormatException e) {
                // fall through to error
            }
            return FormValidation.error(fieldName + " must be a positive integer.");
        }

        public FormValidation doCheckConnectTimeout(@QueryParameter String value) {
            return doCheckTimeoutField(value, "Connect Timeout");
        }

        public FormValidation doCheckSocketTimeout(@QueryParameter String value) {
            return doCheckTimeoutField(value, "Socket Timeout");
        }

        public FormValidation doCheckConnectionRequestTimeout(@QueryParameter String value) {
            return doCheckTimeoutField(value, "Connection Request Timeout");
        }

        // This requires a POST method to protect from CSFR
        @POST
        public FormValidation doTestTowerConnection(
                @QueryParameter("towerURL") final String towerURL,
                @QueryParameter("towerCredentialsId") final String towerCredentialsId,
                @QueryParameter("towerTrustCert") final boolean towerTrustCert,
                @QueryParameter("enableDebugging") final boolean enableDebugging,
                @QueryParameter("connectTimeout") final String connectTimeout,
                @QueryParameter("socketTimeout") final String socketTimeout,
                @QueryParameter("connectionRequestTimeout") final String connectionRequestTimeout
        ) {
            // Also, validate that we are an Administrator
            Jenkins.getInstance().checkPermission(Jenkins.ADMINISTER);
            TowerLogger.writeMessage("Starting to test connection with (" + towerURL + ") and (" + towerCredentialsId + ") and (" + towerTrustCert + ") with debugging (" + enableDebugging + ")");
            TowerConnector testConnector = TowerInstallation.getTowerConnectorStatic(towerURL, towerCredentialsId, towerTrustCert, enableDebugging, null, connectTimeout, socketTimeout, connectionRequestTimeout);
            try {
                testConnector.testConnection();
                return FormValidation.ok("Success");
            } catch (Exception e) {
                return FormValidation.error(e.getMessage());
            }
        }

        // This requires a POST method to protect from CSFR
        @POST
        public ListBoxModel doFillTowerCredentialsIdItems(@AncestorInPath Project project) {
            // Also, validate that we are an Administrator
            Jenkins.getInstance().checkPermission(Jenkins.ADMINISTER);
            return new StandardListBoxModel().withEmptySelection().withMatching(
                    instanceOf(UsernamePasswordCredentials.class),
                    CredentialsProvider.lookupCredentials(StandardUsernameCredentials.class, project)
            ).withMatching(
                    instanceOf(StringCredentials.class),
                    CredentialsProvider.lookupCredentials(StringCredentials.class, project)
            );
        }

        @Override
        public String getDisplayName() {
            return "Tower Installation";
        }
    }
}


