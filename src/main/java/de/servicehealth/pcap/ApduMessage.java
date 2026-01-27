package de.servicehealth.pcap;

import java.util.*;

/**
 * Represents an APDU (Application Protocol Data Unit) command or response
 */
public class ApduMessage {
    private byte[] data;
    private long timestamp;
    private String direction; // "Command" or "Response"
    private Map<String, String> tags;

    public ApduMessage(byte[] data, long timestamp, String direction) {
        this.data = data;
        this.timestamp = timestamp;
        this.direction = direction;
        this.tags = new LinkedHashMap<>();
        parseSicctTags();
    }

    /**
     * Parse SICCT (Smart Card Interface and Core Contract Tags) from APDU data
     */
    private void parseSicctTags() {
        if (data == null || data.length < 2) {
            return;
        }

        int offset = 0;
        
        // Parse Class byte (CLA)
        byte cla = data[offset++];
        tags.put("CLA", String.format("0x%02X", cla));
        
        // Parse Instruction byte (INS)
        if (offset < data.length) {
            byte ins = data[offset++];
            tags.put("INS", String.format("0x%02X", ins));
        }
        
        // Parse Parameter bytes (P1, P2)
        if (offset < data.length) {
            byte p1 = data[offset++];
            tags.put("P1", String.format("0x%02X", p1));
        }
        
        if (offset < data.length) {
            byte p2 = data[offset++];
            tags.put("P2", String.format("0x%02X", p2));
        }

        // Parse Length byte(s) (Lc or Le)
        if (offset < data.length) {
            byte lc = data[offset++];
            if (lc == 0xFF) {
                // Extended length format
                if (offset + 1 < data.length) {
                    int extLen = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
                    tags.put("Lc", String.format("%d (0x%04X)", extLen, extLen));
                    offset += 2;
                }
            } else {
                tags.put("Lc", String.format("%d (0x%02X)", lc & 0xFF, lc));
            }
        }

        // Parse data payload
        if (offset < data.length) {
            int dataLength = data.length - offset;
            if (dataLength > 0) {
                byte[] payload = new byte[Math.min(dataLength, 32)];
                System.arraycopy(data, offset, payload, 0, payload.length);
                tags.put("Data", bytesToHex(payload) + (dataLength > 32 ? "..." : ""));
            }
        }
    }

    /**
     * Convert byte array to hexadecimal string
     */
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString().trim();
    }

    /**
     * Convert hexadecimal string to byte array
     */
    public static byte[] hexToBytes(String hex) {
        String[] hexBytes = hex.split(" ");
        byte[] result = new byte[hexBytes.length];
        for (int i = 0; i < hexBytes.length; i++) {
            result[i] = (byte) Integer.parseInt(hexBytes[i], 16);
        }
        return result;
    }

    // Getters
    public byte[] getData() {
        return data;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public String getDirection() {
        return direction;
    }

    public Map<String, String> getTags() {
        return tags;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("[%s] %s APDU: ", direction, new Date(timestamp)));
        sb.append("CLA=").append(tags.getOrDefault("CLA", "?"));
        sb.append(" INS=").append(tags.getOrDefault("INS", "?"));
        sb.append(" P1=").append(tags.getOrDefault("P1", "?"));
        sb.append(" P2=").append(tags.getOrDefault("P2", "?"));
        if (tags.containsKey("Lc")) {
            sb.append(" Lc=").append(tags.get("Lc"));
        }
        return sb.toString();
    }

    /**
     * Get detailed description of the APDU
     */
    public String getDetailedDescription() {
        StringBuilder sb = new StringBuilder();
        sb.append("\n┌─ APDU Struktur\n");
        
        // CLA Byte
        String claStr = tags.getOrDefault("CLA", "??");
        sb.append("├─ CLA (Klasse): ").append(claStr);
        if (data.length > 0) {
            byte cla = data[0];
            if ((cla & 0x80) == 0) {
                sb.append(" (ISO Standard)");
            } else if ((cla & 0x80) != 0 && (cla & 0x40) == 0) {
                sb.append(" (Proprietärer Format)");
            }
        }
        sb.append("\n");
        
        // INS Byte
        String insStr = tags.getOrDefault("INS", "??");
        sb.append("├─ INS (Instruktion): ").append(insStr);
        if (data.length > 1) {
            String insName = getInstructionName(data[1]);
            if (!insName.isEmpty()) {
                sb.append(" (").append(insName).append(")");
            }
        }
        sb.append("\n");
        
        // Parameter bytes
        sb.append("├─ P1 (Parameter 1): ").append(tags.getOrDefault("P1", "??")).append("\n");
        sb.append("├─ P2 (Parameter 2): ").append(tags.getOrDefault("P2", "??")).append("\n");
        
        // Length
        if (tags.containsKey("Lc")) {
            sb.append("├─ Lc (Datenlänge): ").append(tags.get("Lc")).append("\n");
        }
        
        // Data
        sb.append("├─ Daten (Hex): ").append(tags.getOrDefault("Data", "keine")).append("\n");
        
        // Full hex dump
        sb.append("└─ Vollständige APDU (Hex):\n");
        sb.append("   ").append(bytesToHex(data)).append("\n");
        
        return sb.toString();
    }

    /**
     * Get common instruction names (ISO/IEC 7816-4 standard and proprietary)
     */
    private String getInstructionName(byte ins) {
        switch (ins & 0xFF) {
            // ISO/IEC 7816-4 Standard Instructions
            case 0x00: return "NOP";
            case 0x04: return "DEACTIVATE FILE";
            case 0x0E: return "ERASE RECORD";
            case 0x0F: return "ERASE BINARY";
            case 0x14: return "ERASE BINARY LONG";
            case 0x20: return "VERIFY";
            case 0x24: return "CHANGE REF";
            case 0x2C: return "RESET RETRY COUNTER";
            case 0x44: return "ACTIVATE FILE";
            case 0x70: return "MANAGE CHANNEL (OPEN)";
            case 0x71: return "MANAGE CHANNEL (CLOSE)";
            case 0x82: return "EXTERNAL AUTHENTICATE";
            case 0x84: return "GET CHALLENGE";
            case 0x88: return "AUTHENTICATE";
            case 0xA0: return "SEARCH BINARY";
            case 0xA1: return "SEARCH RECORD";
            case 0xA4: return "SELECT";
            case 0xB0: return "READ BINARY";
            case 0xB1: return "READ BINARY LONG";
            case 0xB2: return "READ RECORD";
            case 0xB3: return "READ RECORD LONG";
            case 0xC0: return "GET RESPONSE";
            case 0xC2: return "ENVELOPE";
            case 0xC3: return "GET CHALLENGE";
            case 0xCA: return "GET DATA";
            case 0xCB: return "GET DATA (TAGGED)";
            case 0xD0: return "WRITE BINARY";
            case 0xD1: return "WRITE BINARY LONG";
            case 0xD2: return "WRITE RECORD";
            case 0xD6: return "UPDATE BINARY";
            case 0xDA: return "PUT DATA";
            case 0xDB: return "PUT DATA (TAGGED)";
            case 0xDC: return "UPDATE RECORD";
            case 0xE0: return "CREATE FILE";
            case 0xE2: return "APPEND RECORD";
            case 0xE4: return "DELETE FILE";
            case 0xE6: return "UPDATE RECORD";
            case 0xE8: return "CREATE RECORD";
            case 0xEA: return "DELETE RECORD";
            case 0xEC: return "TERMINATE CARD USAGE";
            case 0xEE: return "TERMINATE DF";
            
            // Common proprietary/card-specific
            case 0xA8: return "CONSTRUCT DO";
            case 0xAC: return "GET CERTIFICATE";
            case 0xAE: return "SIGN";
            case 0xAF: return "GENERATE KEYPAIR";
            
            default: return "";
        }
    }
}
