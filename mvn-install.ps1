# PowerShell script equivalent of mvn-install.sh
# Sets Java tool options and runs Maven install

$env:JAVA_TOOL_OPTIONS = "-Djavax.xml.accessExternalDTD=all -Djavax.xml.accessExternalSchema=all"
mvn install
