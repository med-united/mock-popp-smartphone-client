package de.servicehealth.cardservice;

import de.servicehealth.pcap.PcapReader;
import de.gematik.ws.conn.connectorcontext.v2.ContextType;
import de.gematik.ws.conn.cardservice.v8.StartCardSessionResponse;
import de.gematik.ws.conn.cardservice.v8.SecureSendAPDUResponse;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

/**
 * Reads APDUs from a PCAP file and sends them as a single signed scenario.
 */
public class PcapSender {

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: mvn exec:java \"-Dexec.mainClass=de.servicehealth.cardservice.PcapSender\" \"-Dexec.args=<pcap_file>\"");
            System.exit(1);
        }

        String pcapFilePath = args[0];
        System.out.println("Reading PCAP file: " + pcapFilePath);

        try {
            // 1. Read APDUs from PCAP
            PcapReader reader = new PcapReader();
            reader.readPcapFile(pcapFilePath);
            List<byte[]> rawApdus = reader.getRawApdus();

            if (rawApdus.isEmpty()) {
                System.out.println("No APDUs found in PCAP file.");
                return;
            }

            System.out.println("Found " + rawApdus.size() + " APDUs.");

            // 2. Convert to Hex Strings
            List<String> apduHexList = new ArrayList<>();
            HexFormat hexFormat = HexFormat.of();
            for (byte[] apdu : rawApdus) {
                String hexApdu = hexFormat.formatHex(apdu);

                if(apduHexList.contains(hexApdu)) {
                    continue;
                }

                apduHexList.add(hexFormat.formatHex(apdu));
            }

            System.out.println("Use " + apduHexList.size() + " distinct APDUs.");

            // 3. Initialize CardService Client
            CardServiceClient client = new CardServiceClient();
            
            client.connectWebSocket("0000-1111");

            // Create Context
            ContextType context = new ContextType();
            context.setMandantId("TestMandant");
            context.setClientSystemId("TestClientSystem");
            context.setWorkplaceId("TestWorkplace");
            context.setUserId("TestUser");

            // 4. Start Card Session
            System.out.println("Starting Card Session...");
            // Note: "0000-1111" is a dummy card handle, adjust if necessary
            StartCardSessionResponse sessionResponse = client.startCardSession(context, "0000-1111");

            if (sessionResponse == null || sessionResponse.getSessionId() == null) {
                System.err.println("Failed to start card session.");
                return;
            }

            String sessionId = sessionResponse.getSessionId();
            System.out.println("Session started. ID: " + sessionId);

            // 5. Create Signed Scenario with ALL APDUs
            System.out.println("Creating signed scenario with " + apduHexList.size() + " steps...");
            //String signedScenario = client.createSignedScenario(sessionId, apduHexList);
            String signedScenario = client.createSignedScenario("0000-1111", apduHexList);

            if ("INVALID_JWT".equals(signedScenario) || "ERROR_CREATING_JWT".equals(signedScenario)) {
                System.err.println("Failed to create signed scenario.");
                return;
            }

            // 6. Send SecureSendApdu
            System.out.println("Sending APDUs...");
            SecureSendAPDUResponse response = client.secureSendApdu(context, signedScenario);

            if (response != null) {
                System.out.println("------------------------------------------------");
                System.out.println("Execution finished.");
                if (response.getStatus() != null) {
                    System.out.println("Result: " + response.getStatus().getResult());
                }
            } else {
                System.err.println("No response received from SecureSendApdu.");
            }

        } catch (IOException e) {
            System.err.println("Error reading PCAP file: " + e.getMessage());
            e.printStackTrace();
        } catch (Exception e) {
            System.err.println("Unexpected error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}