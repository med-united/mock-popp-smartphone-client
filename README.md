# mock-popp-smartphone-client
# Mock Popp Smartphone Client

Dieses Projekt dient als Test-Client und Simulator für das Projekt **popp-smartphone-konnektor**. Es ermöglicht das Testen der SOAP-Schnittstellen für die APDU-Verarbeitung.

## Verwendung der Klassen

### 1. CardServiceClient (`de.servicehealth.cardservice.CardServiceClient`)
Dies ist der zentrale Client für die Kommunikation mit dem Konnektor.
- **Funktion**: 
  - Baut mTLS-gesicherte SOAP-Verbindungen auf.
  - Verwaltet WebSocket-Verbindungen zur Registrierung der eGK (`registerEGK`).
  - Führt die Operationen `StartCardSession`, `SecureSendAPDU` und `StopCardSession` aus.
- **Verwendung**:
  Kann direkt ausgeführt werden, um die Verbindung und Konfiguration zu testen (`testConnection`).
  ```bash
  mvn exec:java -Dexec.mainClass="de.servicehealth.cardservice.CardServiceClient"
  ```

### 2. PcapReader (`de.servicehealth.pcap.PcapReader`)
Ein Werkzeug zur Analyse von Netzwerk-Mitschnitten (PCAP-Dateien).
- **Funktion**: Extrahiert Low-Level APDU-Kommandos aus SICCT-Paketen innerhalb einer PCAP-Datei. Dies hilft beim Debuggen von Kommunikationsabläufen und beim Extrahieren von Testdaten aus echten Aufzeichnungen.
- **Verwendung**:
  ```bash
  mvn exec:java -Dexec.mainClass="de.servicehealth.pcap.PcapReader" -Dexec.args="pfad/zur/datei.pcap" // ohne args wird eine default Datei verwendet
  ```

### 3. PcapSender (`de.servicehealth.cardservice.PcapSender`)
Kombiniert die Funktionalität von Reader und Client für Replay-Szenarien.
- **Funktion**: 
  1. Liest APDUs aus einer angegebenen PCAP-Datei.
  2. Filtert relevante APDUs (nur solche mit bekannten Instruktionen).
  3. Startet eine Kartensitzung am Konnektor.
  4. Sendet die extrahierten APDUs als signedScenario (`SecureSendAPDU`) an den Konnektor.
- **Verwendung**:
  ```bash
  mvn exec:java -Dexec.mainClass="de.servicehealth.cardservice.PcapSender" -Dexec.args="pfad/zur/datei.pcap" // ohne args wird eine default Datei verwendet
  ```

## Konfiguration
Die Konfiguration erfolgt über die Datei `src/main/resources/cardservice.properties`. Hier können Endpunkte, Zertifikate (Keystore/Truststore) und Timeouts angepasst werden.
