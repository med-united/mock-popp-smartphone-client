package de.servicehealth.cardservice;

import org.apache.cxf.endpoint.Client;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.transport.http.HTTPConduit;
import org.apache.cxf.transports.http.configuration.HTTPClientPolicy;

import de.gematik.ws.conn.cardservice.v8.BinaryDocumentType;
import de.gematik.ws.conn.cardservice.v8.SecureSendAPDU;
import de.gematik.ws.conn.cardservice.v8.SecureSendAPDUResponse;
import de.gematik.ws.conn.cardservice.wsdl.v8_2.CardService;
import de.gematik.ws.conn.cardservice.wsdl.v8_2.CardServicePortType;
import oasis.names.tc.dss._1_0.core.schema.SignatureObject;

import jakarta.xml.ws.BindingProvider;
import java.io.File;
import javax.net.ssl.*;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

/**
 * SOAP Client for CardService SecureSendApdu operation
 */
public class CardServiceClient {
    private CardServiceConfig config;
    private CardServicePortType port;

    public CardServiceClient() {
        this.config = new CardServiceConfig();
        initializeClient();
    }

    /**
     * Initialize the SOAP client with configuration
     */
    private void initializeClient() {
        configureSsl();
        
        try {
            // Get the service
            // Use local WSDL to avoid 403 Forbidden on WSDL fetch
            java.net.URL wsdlUrl = getClass().getClassLoader().getResource("wsdl/CardService_v8_2_1.wsdl");
            
            if (wsdlUrl == null) {
                File localWsdl = new File("src/main/resources/wsdl/CardService_v8_2_1.wsdl");
                if (localWsdl.exists()) {
                    wsdlUrl = localWsdl.toURI().toURL();
                } else {
                    throw new java.io.FileNotFoundException("WSDL file not found: wsdl/CardService_v8_2_1.wsdl");
                }
            }

            CardService service = new CardService(wsdlUrl, CardService.SERVICE);
            // Get the port
            port = service.getCardServicePort();
            ((BindingProvider) port).getRequestContext().put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, config.getEndpointUrl());
            
            // Configure HTTP settings
            configureHTTP();
            if (config.isLoggingEnabled()) {
                System.out.println("CardService SOAP Client initialized");
                System.out.println("Endpoint: " + config.getEndpointUrl());
            }
        } catch (Exception e) {
            System.err.println("ERROR initializing CardService client: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Configure HTTP client settings
     */
    private void configureHTTP() {
        Client client = ClientProxy.getClient(port);
        HTTPConduit conduit = (HTTPConduit) client.getConduit();
        HTTPClientPolicy policy = new HTTPClientPolicy();
        
        policy.setConnectionTimeout(config.getConnectionTimeout());
        policy.setReceiveTimeout(config.getSocketTimeout());
        policy.setAllowChunking(false);
        
        conduit.setClient(policy);
    }

    /**
     * Configure SSL: Trust all server certs AND load client certificate (mTLS)
     */
    private void configureSsl() {
        try {
            // 1. Trust Manager (Trust all server certs - for dev/test only!)
            TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) { }
                }
            };

            // 2. Key Manager (Load Client Certificate)
            KeyManager[] keyManagers = null;
            try {
                String keystorePath = config.getSslKeystorePath();
                String keystorePass = config.getSslKeystorePassword();
                
                java.io.InputStream keystoreStream = null;
                File keyFile = new File(keystorePath);
                
                if (keyFile.exists()) {
                    System.out.println("Loading client certificate from file: " + keyFile.getAbsolutePath());
                    keystoreStream = new java.io.FileInputStream(keyFile);
                } else {
                    // Try to load from classpath (handle src/main/resources prefix)
                    String resourcePath = keystorePath;
                    if (resourcePath.startsWith("src/main/resources/")) {
                        resourcePath = resourcePath.substring("src/main/resources/".length());
                    }
                    keystoreStream = getClass().getClassLoader().getResourceAsStream(resourcePath);
                }

                if (keystoreStream == null) {
                    throw new java.io.FileNotFoundException("Keystore file not found: " + keystorePath);
                }
                
                java.security.KeyStore keyStore = java.security.KeyStore.getInstance("PKCS12");
                try (java.io.InputStream fis = keystoreStream) {
                    keyStore.load(fis, keystorePass.toCharArray());
                }
                
                KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                kmf.init(keyStore, keystorePass.toCharArray());
                keyManagers = kmf.getKeyManagers();
                if (config.isLoggingEnabled()) {
                    System.out.println("Client certificate loaded successfully.");
                }
            } catch (Exception e) {
                System.err.println("CRITICAL ERROR: Failed to load client certificate! " + e.getMessage());
                e.printStackTrace();
            }

            // 3. Initialize SSL Context with TLSv1.2 (Required for Gematik)
            System.setProperty("https.protocols", "TLSv1.2");
            System.setProperty("jsse.enableSNIExtension", "false"); // Fix for IP-based access
            
            SSLContext sc = SSLContext.getInstance("TLSv1.2");
            sc.init(keyManagers, trustAllCerts, new SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
        } catch (Exception e) {
            System.err.println("WARNING: Failed to configure SSL: " + e.getMessage());
        }
    }

    /**
     * Call SecureSendApdu operation
     */
    public SecureSendAPDUResponse secureSendApdu(
            BinaryDocumentType transactionData,
            SignatureObject signatureObject,
            byte[] x509Certificate) {
        try {
            if (config.isLoggingEnabled()) {
                System.out.println("Calling SecureSendApdu...");
                System.out.println("  TransactionData length: " + transactionData.getBase64Data().getValue().length);
                System.out.println("  SignatureObject: " + (signatureObject != null ? "present" : "null"));
                System.out.println("  X509Certificate: " + (x509Certificate != null ? "present" : "null"));
            }

            SecureSendAPDU request = new SecureSendAPDU();
            request.setTransactionData(transactionData);
            request.setSignatureObject(signatureObject);
            request.setX509Certificate(x509Certificate);

            SecureSendAPDUResponse response = port.secureSendAPDU(request);

            if (config.isLoggingEnabled()) {
                System.out.println("SecureSendApdu response received");
                System.out.println("  Status: " + (response.getStatus() != null ? response.getStatus() : "null"));
                System.out.println("  TransactionResult length: " + 
                    (response.getTransactionResult() != null ? response.getTransactionResult().getBase64Data().getValue().length : 0));
                System.out.println("  TimeSpan: " + response.getTimeSpan());
            }

            return response;
        } catch (Exception e) {
            System.err.println("ERROR calling SecureSendApdu: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Get the configuration object
     */
    public CardServiceConfig getConfig() {
        return config;
    }

    /**
     * Test the connection
     */
    public boolean testConnection() {
        try {
            if (port == null) {
                System.err.println("ERROR: Port not initialized");
                return false;
            }
            
            if (config.isLoggingEnabled()) {
                System.out.println("Testing connection to " + config.getEndpointUrl() + "...");
            }

            // Send an empty request to provoke a response from the server.
            // Even a SOAP Fault proves that SSL handshake and HTTP connection are working.
            try {
                port.secureSendAPDU(new SecureSendAPDU());
                System.out.println("Connection test: OK (Service responded)");
            } catch (jakarta.xml.ws.soap.SOAPFaultException e) {
                System.out.println("Connection test: OK (Server reachable, returned Fault: " + e.getMessage() + ")");
            } catch (Exception e) {
                // Check for network/SSL errors
                String msg = e.getMessage();
                if (msg != null && (msg.contains("Failed to access") || msg.contains("Connection refused") || msg.contains("Handshake") || msg.contains("timed out"))) {
                    throw e;
                }
                System.out.println("Connection test: OK (Server reachable but returned error: " + e.getMessage() + ")");
            }
            
            return true;
        } catch (Exception e) {
            System.err.println("Connection test failed: " + e.getMessage());
            return false;
        }
    }

    public static void main(String[] args) {
        System.setProperty("javax.xml.accessExternalDTD", "all");
        System.setProperty("javax.xml.accessExternalSchema", "all");
        CardServiceClient client = new CardServiceClient();
        
        if (client.testConnection()) {
            System.out.println("CardService client is ready");
            System.out.println("Endpoint: " + client.getConfig().getEndpointUrl());
        } else {
            System.err.println("Failed to initialize CardService client");
            System.exit(1);
        }
    }
}
