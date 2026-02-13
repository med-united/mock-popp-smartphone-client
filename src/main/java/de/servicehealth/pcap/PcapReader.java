package de.servicehealth.pcap;

import java.io.*;
import java.util.*;
import java.util.stream.Collectors;

/**
 * PCAP Reader for extracting APDU/SICCT messages from network captures
 */
public class PcapReader {
    private static final byte[] PCAP_MAGIC = {(byte) 0xD4, (byte) 0xC3, (byte) 0xB2, (byte) 0xA1};
    private static final byte[] PCAP_MAGIC_BE = {(byte) 0xA1, (byte) 0xB2, (byte) 0xC3, (byte) 0xD4};

    private List<ApduMessage> apduMessages;
    private List<byte[]> rawApdus;
    private boolean bigEndian;

    public PcapReader() {
        this.apduMessages = new ArrayList<>();
        this.rawApdus = new ArrayList<>();
        this.bigEndian = false;
    }

    /**
     * Read and parse a PCAP file
     */
    public List<ApduMessage> readPcapFile(String filePath) throws IOException {
        File file = new File(filePath);
        if (!file.exists()) {
            throw new FileNotFoundException("PCAP file not found: " + filePath);
        }

        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] magicBuffer = new byte[4];
            fis.read(magicBuffer);

            // Check PCAP magic number
            if (Arrays.equals(magicBuffer, PCAP_MAGIC)) {
                bigEndian = false;
            } else if (Arrays.equals(magicBuffer, PCAP_MAGIC_BE)) {
                bigEndian = true;
            } else {
                throw new IOException("Invalid PCAP file format. Magic number not recognized.");
            }

            // Skip global header (24 bytes total, 4 already read)
            fis.skip(20);

            // Read packet records
            byte[] packetBuffer = new byte[65536];
            while (true) {
                byte[] packetHeader = new byte[16];
                int bytesRead = fis.read(packetHeader);
                
                if (bytesRead < 16) {
                    break; // End of file
                }

                // Parse packet header
                long timestamp = readInt(packetHeader, 0);
                int incLen = readInt(packetHeader, 8);
                
                if (incLen > packetBuffer.length) {
                    packetBuffer = new byte[incLen + 1000];
                }

                // Read packet data
                fis.read(packetBuffer, 0, incLen);
                
                // Extract APDU from packet data
                extractApduFromPacket(packetBuffer, incLen, timestamp);
            }
        }

        return apduMessages;
    }

    /**
     * Extract APDU messages from raw packet data
     */
    private void extractApduFromPacket(byte[] packet, int length, long timestamp) {
        // Skip typical network headers:
        // - Ethernet: 14 bytes
        // - IP (IPv4): 20 bytes
        // - TCP: 20 bytes
        // Total: 54 bytes
        
        int minHeaderSize = 54;
        if (length <= minHeaderSize) {
            return;
        }

        // Start after network headers at offset 54
        int offset = 54;
        int payloadLength = length - offset;
        
        if (payloadLength < 10) {
            return; // SICCT header minimum size
        }

        byte[] payload = new byte[payloadLength];
        System.arraycopy(packet, offset, payload, 0, payloadLength);
        
        // Try to extract SICCT and APDU data
        List<byte[]> apdus = extractFromSicctData(payload);
        for (byte[] apdu : apdus) {
            if (isValidApdu(apdu)) {
                rawApdus.add(apdu);
                ApduMessage apduMsg = new ApduMessage(apdu, timestamp, "Packet");
                apduMessages.add(apduMsg);
            }
        }
    }

    /**
     * Extract APDUs from SICCT Protocol Data
     * 
     * SICCT PDU Header structure:
     * Byte 0:     messageType (e.g., 0x6b)
     * Byte 1-2:   srcCorDesAddr (2 bytes, little-endian)
     * Byte 3-4:   seq (sequence number, little-endian)
     * Byte 5:     abRFU (reserved for future use)
     * Byte 6-9:   dwLength (payload length, 4 bytes, little-endian)
     * Byte 10+:   Payload (APDU)
     */
    private List<byte[]> extractFromSicctData(byte[] data) {
        List<byte[]> results = new ArrayList<>();
        
        if (data.length < 10) {
            return results;
        }
        
        // Extract dwLength from bytes 6-9 (4 bytes, little-endian)
        int dwLength = ((data[6] & 0xFF) | 
                       ((data[7] & 0xFF) << 8) |
                       ((data[8] & 0xFF) << 16) |
                       ((data[9] & 0xFF) << 24));
        
        // Validate dwLength
        if (dwLength > 0 && dwLength < 10000 && 10 + dwLength <= data.length) {
            // Extract payload according to dwLength
            byte[] payload = new byte[dwLength];
            System.arraycopy(data, 10, payload, 0, dwLength);
            results.add(payload);
        } else {
            // Fallback: try remaining data as APDU
            if (data.length > 10) {
                byte[] payload = new byte[data.length - 10];
                System.arraycopy(data, 10, payload, 0, payload.length);
                results.add(payload);
            }
        }
        
        return results;
    }

    /**
     * Check if data looks like a valid APDU
     */
    private boolean isValidApdu(byte[] data) {
        if (data.length < 4) {
            return false;
        }

        byte cla = data[0];
        byte ins = data[1];
        
        // Valid APDU characteristics:
        // - CLA byte: common values are 0x00, 0x80, 0xA0, 0xA4, 0xB0, 0xC0, 0xD0, 0xD2, 0x84, 0x88
        // - INS byte: should be a valid instruction
        // - Both should not be 0xFF (that's typically padding)
        
        return cla != (byte)0xFF && ins != (byte)0xFF && (cla & 0x0F) <= 0x0F;
    }

    /**
     * Read 32-bit integer (handles endianness)
     */
    private int readInt(byte[] data, int offset) {
        int value;
        if (bigEndian) {
            value = ((data[offset] & 0xFF) << 24) |
                    ((data[offset + 1] & 0xFF) << 16) |
                    ((data[offset + 2] & 0xFF) << 8) |
                    (data[offset + 3] & 0xFF);
        } else {
            value = (data[offset] & 0xFF) |
                    ((data[offset + 1] & 0xFF) << 8) |
                    ((data[offset + 2] & 0xFF) << 16) |
                    ((data[offset + 3] & 0xFF) << 24);
        }
        return value;
    }

    /**
     * Get list of extracted APDU messages
     */
    public List<ApduMessage> getApduMessages() {
        return apduMessages;
    }

    /**
     * Get list of raw APDU bytes
     */
    public List<byte[]> getRawApdus() {
        return rawApdus;
    }

    /**
     * Get list of APDUs that have a known instruction name
     */
    public List<ApduMessage> getApdusWithKnownInstructions() {
        return apduMessages.stream().filter(a -> !a.getInstructionName().isEmpty()).collect(Collectors.toList());
    }

    /**
     * Get list of raw APDU bytes that have a known instruction name
     */
    public List<byte[]> getRawApdusWithKnownInstructions() {
        return apduMessages.stream()
                .filter(a -> !a.getInstructionName().isEmpty())
                .map(ApduMessage::getData)
                .collect(Collectors.toList());
    }

    /**
     * Print summary of extracted APDUs
     */
    public void printSummary() {
        List<ApduMessage> apduMessages = getApdusWithKnownInstructions();

        System.out.println("\nTotal APDU Messages with known instructions: " + apduMessages.size());
        
        if (apduMessages.isEmpty()) {
            System.out.println("Keine APDUs in der PCAP-Datei gefunden.");
            return;
        }
        
        System.out.println("\n" + "=".repeat(70) + "\n");
        for (int i = 0; i < apduMessages.size(); i++) {
            ApduMessage apdu = apduMessages.get(i);
            System.out.println("APDU #" + (i + 1) + ": " + apdu);
            System.out.print(apdu.getDetailedDescription());
            System.out.println("─".repeat(70) + "\n");
        }
    }

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: mvn exec:java \"-Dexec.mainClass=de.servicehealth.pcap.PcapReader\" \"-Dexec.args=<pcap_file>\"");
            System.out.println("Example: mvn exec:java \"-Dexec.mainClass=de.servicehealth.pcap.PcapReader\" \"-Dexec.args=src/main/resources/pcap/capture.pcap\"");
            System.out.println("Default file is used");
        }

        try {
            PcapReader reader = new PcapReader();
            List<ApduMessage> apdus = reader.readPcapFile((args.length > 0 ? args[0] : "src/main/resources/pcap/connect-gsmc-kt-card-handle-vsdm.pcap"));
            reader.printSummary();
        } catch (IOException e) {
            System.err.println("Error reading PCAP file: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
