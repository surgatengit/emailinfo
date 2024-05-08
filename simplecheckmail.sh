#!/bin/bash

BLUE='\033[0;34m'
GREEN='\033[0;32m' 
YELLOW='\033[1;33m' 
RED='\033[0;31m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
GRAY='\033[0;37m'
LIGHT_BLUE='\033[1;34m'
LIGHT_GREEN='\033[1;32m'
LIGHT_YELLOW='\033[1;33m'
LIGHT_RED='\033[1;31m'
LIGHT_CYAN='\033[1;36m'
LIGHT_PURPLE='\033[1;35m'
WHITE='\033[1;37m'
NC='\033[0m' # No color


# Verificar si dig está instalado
if ! command -v dig &> /dev/null; then
    echo "El comando 'dig' no está instalado en tu sistema."
    echo "Por favor, instálalo para continuar. Puedes instalarlo usando el siguiente comando:"
    echo "Para Ubuntu/Debian: sudo apt-get install dnsutils"
    echo "Para CentOS/RHEL: sudo yum install bind-utils"
    exit 1
fi

# Verificar si nslookup está instalado
if ! command -v nslookup &> /dev/null; then
    echo "El comando 'nslookup' no está instalado en tu sistema."
    echo "Por favor, instálalo para continuar. Puedes instalarlo usando el siguiente comando:"
    echo "Para Ubuntu/Debian: sudo apt-get install dnsutils"
    echo "Para CentOS/RHEL: sudo yum install bind-utils"
    exit 1
fi

# Función para mostrar la información de SPF
function mostrar_spf_info {
    echo "------------------------------------------------------------------"
    echo "Información de SPF:"
    echo ""
    echo "SPF (Sender Policy Framework) es un mecanismo de autenticación de correo electrónico"
    echo "diseñado para prevenir el correo electrónico no autorizado mediante la validación"
    echo "de las direcciones IP autorizadas para enviar correo en nombre de un dominio específico."
    echo "Es importante para evitar el spoofing de correo electrónico."
    echo ""
    echo "Registros SPF encontrados para $1:"
    spf_info=$(dig +short TXT $1 | grep spf)
    if [ -z "$spf_info" ]; then
        echo -e "${LIGHT_BLUE}SPF no está configurado para este dominio. Es vulnerable a spoofing.${NC}"
    else
        echo -e "${LIGHT_BLUE}$spf_info ${NC}"
    fi
    echo ""
}

# Función para mostrar la información de DMARC
function mostrar_dmarc_info {
    echo "------------------------------------------------------------------"
    echo "Información de DMARC:"
    echo ""
    echo "DMARC (Domain-based Message Authentication, Reporting, and Conformance) es una política"
    echo "de autenticación de correo electrónico que utiliza SPF y DKIM para ayudar a proteger"
    echo "contra el correo electrónico no autorizado y el phishing."
    echo ""
    echo "Registros DMARC encontrados para $1:"
    dmarc_info=$(dig +short TXT _dmarc.$1)
    if [ -z "$dmarc_info" ]; then
        echo -e "${LIGHT_BLUE}DMARC no está configurado para este dominio. Es vulnerable a spoofing. ${NC}"
    else
        echo -e "${LIGHT_BLUE}$dmarc_info ${NC}"
    fi
    echo ""
}

# Función mostrar los servidores de correo MX
function mostrar_servidores_MX {
    echo "------------------------------------------------------------------"
    echo "Información MX:"
    echo ""
    echo "MX (Mail eXchange record) Los registros MX apuntan a los servidores"
    echo "a los cuales envían un correo electrónico,"
    echo "y a cuál de ellos debería ser enviado en primer lugar, por prioridad. "
    echo ""
    echo "Servidores de correo encontrados $1:"
    servidores_MX=$(dig +noall +answer -t MX $1)
    echo -e "${LIGHT_BLUE}$servidores_MX ${NC}"

}
# Función principal
function main {
    # Solicitar al usuario que ingrese el dominio
    read -p "Por favor, ingrese el nombre de dominio: " dominio

    echo ""
    echo "------------------------------------------------------------------"
    echo "Verificación de seguridad para el dominio: $dominio"
    echo "------------------------------------------------------------------"

    # Mostrar información de SPF
    mostrar_spf_info $dominio

    # Mostrar información de DMARC
    mostrar_dmarc_info $dominio

    # Mostrar los servidores de correo MX
    mostrar_servidores_MX $dominio

}

# Llamar a la función principal
main
