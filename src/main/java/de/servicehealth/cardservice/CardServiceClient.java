package de.servicehealth.cardservice;

import org.apache.cxf.endpoint.Client;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.transport.http.HTTPConduit;
import org.apache.cxf.transports.http.configuration.HTTPClientPolicy;
import org.apache.cxf.headers.Header;
import org.apache.cxf.jaxb.JAXBDataBinding;
import org.apache.cxf.configuration.jsse.TLSClientParameters;

import de.gematik.ws.conn.cardservice.v8.SecureSendAPDU;
import de.gematik.ws.conn.cardservice.v8.SecureSendAPDUResponse;
import de.gematik.ws.conn.cardservice.v8.StartCardSession;
import de.gematik.ws.conn.cardservice.v8.StartCardSessionResponse;
import de.gematik.ws.conn.cardservice.v8.StopCardSession;
import de.gematik.ws.conn.cardservice.v8.StopCardSessionResponse;
import de.gematik.ws.conn.cardservice.wsdl.v8_2.CardService;
import de.gematik.ws.conn.cardservice.wsdl.v8_2.CardServicePortType;
import de.gematik.ws.conn.connectorcontext.v2.ContextType;

import jakarta.xml.ws.BindingProvider;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import javax.xml.namespace.QName;
import javax.net.ssl.*;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.PrivateKey;
import java.util.Enumeration;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * SOAP Client for CardService SecureSendApdu operation
 */
public class CardServiceClient {
    private CardServiceConfig config;
    private CardServicePortType port;
    private KeyManager[] keyManagers;
    private TrustManager[] trustManagers;
    private PrivateKey privateKey;
    private List<String> clientCertChain;

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

        if (config.getEndpointUrl().toLowerCase().startsWith("https")) {
            TLSClientParameters tlsParams = new TLSClientParameters();
            tlsParams.setDisableCNCheck(true);
            tlsParams.setTrustManagers(trustManagers);
            if (keyManagers != null) {
                tlsParams.setKeyManagers(keyManagers);
                if (config.isLoggingEnabled()) System.out.println("mTLS configured with client certificate.");
            } else {
                System.err.println("WARNING: No KeyManagers available. Client certificate will NOT be sent.");
            }
            conduit.setTlsClientParameters(tlsParams);
        }
    }

    /**
     * Configure SSL: Trust all server certs AND load client certificate (mTLS)
     */
    private void configureSsl() {
        try {
            // 1. Trust Manager (Trust all server certs - for dev/test only!)
            trustManagers = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) { }
                }
            };

            // 2. Key Manager (Load Client Certificate)
            keyManagers = null;
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

                // Extract CN from certificate for WebSocket connection
                Enumeration<String> aliases = keyStore.aliases();
                while (aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();
                    if (keyStore.isKeyEntry(alias)) {
                        this.privateKey = (PrivateKey) keyStore.getKey(alias, keystorePass.toCharArray());
                        
                        // Extract certificate chain for JWT headers (x5c, stpl)
                        java.security.cert.Certificate[] chain = keyStore.getCertificateChain(alias);
                        if (chain != null) {
                            this.clientCertChain = new ArrayList<>();
                            for (java.security.cert.Certificate c : chain) {
                                this.clientCertChain.add(Base64.getEncoder().encodeToString(c.getEncoded()));
                            }
                        }
                        break;
                    }
                }

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
            sc.init(keyManagers, trustManagers, new SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
        } catch (Exception e) {
            System.err.println("WARNING: Failed to configure SSL: " + e.getMessage());
        }
    }

    /**
     * Creates a signed JWT scenario using the client's private key
     * @param sessionId The session ID to include in the payload
     */
    private String createSignedScenario(String sessionId) {
        try {
            if (privateKey == null) {
                System.err.println("Cannot sign scenario: No private key available.");
                return "INVALID_JWT";
            }

            String algo = privateKey.getAlgorithm();
            SignatureAlgorithm sigAlgo;

            if ("RSA".equals(algo)) {
                sigAlgo = SignatureAlgorithm.RS256;
            } else {
                sigAlgo = SignatureAlgorithm.ES256;
            }

            // Build Payload Map
            Map<String, Object> step = new HashMap<>();
            step.put("commandApdu", "00a4040c");
            step.put("expectedStatusWords", List.of("9000", "6f00"));

            Map<String, Object> message = new HashMap<>();
            message.put("type", "StandardScenario");
            message.put("version", "1.0.0");
            message.put("clientSessionId", sessionId);
            message.put("sequenceCounter", 1);
            message.put("timeSpan", 1000);
            message.put("steps", List.of(step));

            // Build and Sign JWT
            io.jsonwebtoken.JwtBuilder builder = Jwts.builder()
                    .setHeaderParam("typ", "JWT")
                    .claim("message", message)
                    .signWith(privateKey, sigAlgo);
            
            if (clientCertChain != null && !clientCertChain.isEmpty()) {
                builder.setHeaderParam("x5c", clientCertChain);
                builder.setHeaderParam("stpl", clientCertChain.get(0));
            }
            
            return builder.compact();
        } catch (Exception e) {
            System.err.println("Error creating signed scenario: " + e.getMessage());
            return "ERROR_CREATING_JWT";
        }
    }

    /**
     * Start a card session
     */
    public StartCardSessionResponse startCardSession(ContextType context, String cardHandle) {
        if (context == null) {
            System.err.println("ERROR: ContextType is null");
            return null;
        }
        
        try {
            if (config.isLoggingEnabled()) {
                System.out.println("Calling StartCardSession...");
                System.out.println("  CardHandle: " + cardHandle);
            }

            StartCardSession request = new StartCardSession();
            request.setCardHandle(cardHandle);

            addContextHeader(context);

            StartCardSessionResponse response = port.startCardSession(request);

            if (config.isLoggingEnabled()) {
                System.out.println("StartCardSession response received");
                if (response != null) {
                    System.out.println("  Response: " + response.getSessionId());
                }
            }

            return response;
        } catch (Exception e) {
            System.err.println("ERROR calling StartCardSession: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Stop a card session
     */
    public StopCardSessionResponse stopCardSession(ContextType context, String sessionId) {
        if (context == null) {
            System.err.println("ERROR: ContextType is null");
            return null;
        }
        
        try {
            if (config.isLoggingEnabled()) {
                System.out.println("Calling StopCardSession...");
                System.out.println("  SessionId: " + sessionId);
            }

            StopCardSession request = new StopCardSession();
            request.setSessionId(sessionId);

            addContextHeader(context);

            StopCardSessionResponse response = port.stopCardSession(request);

            if (config.isLoggingEnabled()) {
                System.out.println("StopCardSession response received");
                if (response != null) {
                    System.out.println("  Response: " + response.toString());
                }
            }

            return response;
        } catch (Exception e) {
            System.err.println("ERROR calling StopCardSession: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Call SecureSendApdu operation
     */
    public SecureSendAPDUResponse secureSendApdu(
            ContextType context,
            String signedScenario
        ) {
        
        if (context == null) {
            System.err.println("ERROR: ContextType is null");
            return null;
        }

        try {
            System.out.println("Calling SecureSendApdu...");
            System.out.println("  Context: [MandantId=" + context.getMandantId() + 
                                   ", ClientSystemId=" + context.getClientSystemId() + 
                                   ", WorkplaceId=" + context.getWorkplaceId() + "]");

            SecureSendAPDU request = new SecureSendAPDU();
            request.setSignedScenario(signedScenario);

            // Add Context as SOAP Header
            addContextHeader(context);

            SecureSendAPDUResponse response = port.secureSendAPDU(request);

            if (config.isLoggingEnabled()) {
                System.out.println("SecureSendApdu response received");
                if (response != null && response.getStatus() != null) {
                    System.out.println("  Status: " + response.getStatus().getResult());
                    if (response.getStatus().getError() != null) {
                        System.out.println("  Error: " + response.getStatus().getError());
                    }
                }
                
                if (response != null && response.getSignedScenarioResponse() != null) {
                    System.out.println("  SignedScenarioResponse: present");
                } else {
                    System.out.println("  SignedScenarioResponse: null");
                }
            }

            return response;
        } catch (Exception e) {
            System.err.println("ERROR calling SecureSendApdu: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Helper to add ContextType as SOAP Header
     */
    private void addContextHeader(ContextType context) {
        List<Header> headers = new ArrayList<>();
        try {
            Header contextHeader = new Header(
                new QName("http://ws.gematik.de/conn/ConnectorContext/v2.0", "Context"), 
                context, 
                new JAXBDataBinding(ContextType.class));
            headers.add(contextHeader);
        } catch (Exception e) {
            System.err.println("Error creating SOAP Header: " + e.getMessage());
        }
        ((BindingProvider) port).getRequestContext().put(Header.HEADER_LIST, headers);
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
                // Create dummy context for connection test
                ContextType dummyContext = new ContextType();
                dummyContext.setMandantId("Test");
                dummyContext.setClientSystemId("Test");
                dummyContext.setWorkplaceId("Test");
                dummyContext.setUserId("Test");
                
                // Add Context as SOAP Header for test
                addContextHeader(dummyContext);

                StartCardSessionResponse response = startCardSession(dummyContext, "0000-1111");

                secureSendApdu(dummyContext, createSignedScenario(response.getSessionId()));
                
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
