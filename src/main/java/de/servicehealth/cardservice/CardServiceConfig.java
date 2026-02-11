package de.servicehealth.cardservice;

import java.io.*;
import java.util.List;
import java.util.Properties;

/**
 * Configuration loader for CardService SOAP Client
 */
public class CardServiceConfig {
    private static final String CONFIG_FILE = "cardservice.properties";
    private Properties properties;

    public CardServiceConfig() {
        properties = new Properties();
        loadConfiguration();
    }

    /**
     * Load configuration from properties file
     */
    private void loadConfiguration() {
        try (InputStream input = CardServiceConfig.class
                .getClassLoader()
                .getResourceAsStream(CONFIG_FILE)) {
            if (input == null) {
                System.err.println("WARNING: " + CONFIG_FILE + " not found. Using defaults.");
                setDefaults();
                return;
            }
            properties.load(input);
        } catch (IOException e) {
            System.err.println("ERROR loading configuration: " + e.getMessage());
            setDefaults();
        }
    }

    /**
     * Set default values
     */
    private void setDefaults() {
        properties.setProperty("cardservice.endpoint.url", "http://localhost:8443/services/CardService");
        properties.setProperty("cardservice.connection.timeout", "30000");
        properties.setProperty("cardservice.socket.timeout", "30000");
        properties.setProperty("cardservice.ssl.enabled", "false");
        properties.setProperty("cardservice.proxy.enabled", "false");
        properties.setProperty("cardservice.logging.enabled", "true");
    }

    // Getters
    public String getEndpointUrl() {
        return properties.getProperty("cardservice.endpoint.url");
    }

    public int getConnectionTimeout() {
        return Integer.parseInt(
            properties.getProperty("cardservice.connection.timeout", "30000")
        );
    }

    public int getSocketTimeout() {
        return Integer.parseInt(
            properties.getProperty("cardservice.socket.timeout", "30000")
        );
    }

    public boolean isSslEnabled() {
        return Boolean.parseBoolean(
            properties.getProperty("cardservice.ssl.enabled", "false")
        );
    }

    public String getSslTruststorePath() {
        return properties.getProperty("cardservice.ssl.truststore.path", "");
    }

    public String getSslTruststorePassword() {
        return properties.getProperty("cardservice.ssl.truststore.password", "");
    }

    public String getSslKeystorePath() {
        return properties.getProperty("cardservice.ssl.keystore.path", "client.p12");
    }

    public String getSslKeystorePassword() {
        return properties.getProperty("cardservice.ssl.keystore.password", "000000");
    }

    public boolean isProxyEnabled() {
        return Boolean.parseBoolean(
            properties.getProperty("cardservice.proxy.enabled", "false")
        );
    }

    public String getProxyHost() {
        return properties.getProperty("cardservice.proxy.host", "");
    }

    public int getProxyPort() {
        return Integer.parseInt(
            properties.getProperty("cardservice.proxy.port", "8080")
        );
    }

    public boolean isLoggingEnabled() {
        return Boolean.parseBoolean(
            properties.getProperty("cardservice.logging.enabled", "true")
        );
    }

    public String getLoggingLevel() {
        return properties.getProperty("cardservice.logging.level", "INFO");
    }

    public String getWsdlPath() {
    return properties.getProperty("cardservice.wsdl.path", "wsdl/CardService_v8_2_1.wsdl");
    }

    public String getWebsocketPathTemplate() {
        return properties.getProperty("cardservice.websocket.path.template", "/websocket/{cn}");
    }

    public String getWebsocketRegisterType() {
        return properties.getProperty("cardservice.websocket.register.type", "registerEGK");
    }

    public String getScenarioType() {
        return properties.getProperty("cardservice.scenario.type", "StandardScenario");
    }

    public String getScenarioVersion() {
        return properties.getProperty("cardservice.scenario.version", "1.0.0");
    }

    public int getScenarioSequenceCounter() {
        return Integer.parseInt(properties.getProperty("cardservice.scenario.sequenceCounter", "1"));
    }

    public int getScenarioTimeSpan() {
        return Integer.parseInt(properties.getProperty("cardservice.scenario.timeSpan", "1000"));
    }

    public List<String> getScenarioExpectedStatusWords() {
        String csv = properties.getProperty("cardservice.scenario.expectedStatusWords", "9000,6f00");
        return java.util.Arrays.stream(csv.split(","))
                .map(String::trim)
                .filter(s -> !s.isBlank())
                .toList();
    }

    public String getTestCardHandle() {
        return properties.getProperty("cardservice.test.cardHandle", "0000-1111");
    }

    public List<String> getTestApdus() {
        String csv = properties.getProperty("cardservice.test.apdus", "00a4040c");
        return java.util.Arrays.stream(csv.split(","))
                .map(String::trim)
                .filter(s -> !s.isBlank())
                .toList();
    }

}
