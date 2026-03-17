#!/bin/bash
#
# email-audit.sh — Auditoría completa de autenticación de correo electrónico
# Verifica MX, SPF, DKIM, DMARC, DANE/TLSA, MTA-STS, TLS-RPT, BIMI,
# certificados TLS y protección de subdominios.
#
# Uso: ./email-audit.sh [dominio]
#       Si no se pasa argumento, lo solicita de forma interactiva.
#
# Dependencias obligatorias: dig
# Dependencias opcionales:   openssl (TLS/certs), curl (MTA-STS policy)
#                             nc + timeout (STARTTLS básico)

set -uo pipefail

# ─── Colores ──────────────────────────────────────────────────────────
BOLD='\033[1m'
DIM='\033[2m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
NC='\033[0m'

OK="${GREEN}✓${NC}"
WARN="${YELLOW}⚠${NC}"
FAIL="${RED}✗${NC}"
INFO="${CYAN}ℹ${NC}"

SCORE=0
MAX_SCORE=0
MX_SERVERS=()
TIENE_MX=false
TIENE_OPENSSL=false
TIENE_CURL=false

W=62  # ancho interno recuadro

sumar_puntos() {
    SCORE=$((SCORE + $1))
    MAX_SCORE=$((MAX_SCORE + $2))
}

# ─── Utilidades de recuadro ──────────────────────────────────────────
linea_recuadro() {
    local texto="$1"
    local visible
    visible=$(printf '%b' "$texto" | sed 's/\x1b\[[0-9;]*m//g')
    local len=${#visible}
    local pad=$((W - len))
    if [[ $pad -lt 0 ]]; then pad=0; fi
    printf "${CYAN}║${NC}%b%*s${CYAN}║${NC}\n" "$texto" "$pad" ""
}

linea_vacia() {
    printf "${CYAN}║${NC}%*s${CYAN}║${NC}\n" "$W" ""
}

L() {
    local texto="${1:-}"
    printf "${BLUE}│${NC} %b\n" "$texto"
}

LV() {
    printf "${BLUE}│${NC}\n"
}

seccion_inicio() {
    printf "${BLUE}┌──────────────────────────────────────────────────────────────┐${NC}\n"
}

seccion_fin() {
    printf "${BLUE}└──────────────────────────────────────────────────────────────┘${NC}\n\n"
}

safe_dig() {
    dig "$@" 2>/dev/null || true
}

# ─── Comprobación de dependencias ────────────────────────────────────
comprobar_dependencias() {
    if ! command -v dig &>/dev/null; then
        printf "${RED}Error:${NC} Falta el comando 'dig'.\n"
        printf "Instálalo con:\n"
        printf "  Debian/Ubuntu: sudo apt-get install dnsutils\n"
        printf "  CentOS/RHEL:   sudo yum install bind-utils\n"
        printf "  macOS:         brew install bind\n"
        exit 1
    fi

    if command -v openssl &>/dev/null; then
        TIENE_OPENSSL=true
    fi

    if command -v curl &>/dev/null; then
        TIENE_CURL=true
    fi
}

# ─── Validar formato de dominio ──────────────────────────────────────
validar_dominio() {
    if [[ ! "$1" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$ ]]; then
        printf "${RED}Error:${NC} '%s' no parece un dominio válido.\n" "$1"
        exit 1
    fi
}

# ─── Verificar que el dominio existe en DNS ──────────────────────────
verificar_dominio_existe() {
    local dominio="$1"
    local cualquier_registro
    cualquier_registro=$(safe_dig +short ANY "$dominio" || true)
    if [[ -z "$cualquier_registro" ]]; then
        cualquier_registro=$(safe_dig +short A "$dominio" || true)
    fi
    if [[ -z "$cualquier_registro" ]]; then
        cualquier_registro=$(safe_dig +short NS "$dominio" || true)
    fi
    if [[ -z "$cualquier_registro" ]]; then
        printf "\n"
        printf "${RED}══════════════════════════════════════════════════════════════${NC}\n"
        printf "${RED}  ✗ El dominio '%s' no tiene registros DNS.${NC}\n" "$dominio"
        printf "${RED}  ¿Está bien escrito? Comprueba que no haya erratas.${NC}\n"
        printf "${RED}══════════════════════════════════════════════════════════════${NC}\n"
        printf "\n"
        exit 1
    fi
}

# ─── Banner ──────────────────────────────────────────────────────────
mostrar_banner() {
    local dominio="$1"
    local fecha
    fecha=$(date '+%Y-%m-%d %H:%M:%S')

    # Detectar herramientas opcionales disponibles
    local extras=""
    if [[ "$TIENE_OPENSSL" == true ]]; then extras+="openssl "; fi
    if [[ "$TIENE_CURL" == true ]]; then extras+="curl "; fi
    if command -v nc &>/dev/null; then extras+="nc "; fi
    if [[ -z "$extras" ]]; then extras="ninguna"; fi

    printf "\n"
    printf "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}\n"
    linea_vacia
    linea_recuadro "${BOLD}      AUDITORÍA DE AUTENTICACIÓN DE CORREO ELECTRÓNICO${NC}"
    linea_vacia
    printf "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}\n"
    linea_recuadro "  Dominio:  ${dominio}"
    linea_recuadro "  Fecha:    ${fecha}"
    linea_recuadro "  Checks:   MX · SPF · DKIM · DMARC · DANE/TLSA"
    linea_recuadro "            MTA-STS · TLS-RPT · BIMI · TLS · Subdominios"
    linea_recuadro "  Extras:   ${extras}"
    printf "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}\n"
    printf "\n"
}

# ═════════════════════════════════════════════════════════════════════
# 1. MX
# ═════════════════════════════════════════════════════════════════════
auditar_mx() {
    local dominio="$1"
    seccion_inicio
    L "${BOLD}1. MX (Mail eXchange)${NC}"
    L "${DIM}Servidores responsables de recibir correo para el dominio.${NC}"
    L "${DIM}Sin registros MX el dominio no puede recibir email. La prioridad${NC}"
    L "${DIM}(número menor = preferido) determina el orden de entrega.${NC}"
    LV

    local mx
    mx=$(safe_dig +short MX "$dominio" | sort -n || true)

    if [[ -z "$mx" ]]; then
        L " ${FAIL} No se encontraron registros MX"
        L "   ${YELLOW}→ Este dominio no puede recibir correo${NC}"
        sumar_puntos 0 2
        TIENE_MX=false
        seccion_fin
        return
    fi

    TIENE_MX=true

    L " ${OK} Servidores MX encontrados:"
    LV
    L "   ${DIM}$(printf '%-12s %-45s' "PRIORIDAD" "SERVIDOR")${NC}"
    L "   ${DIM}$(printf '%-12s %-45s' "─────────" "────────────────────────────────")${NC}"

    MX_SERVERS=()

    while IFS= read -r linea; do
        [[ -z "$linea" ]] && continue
        local prioridad servidor
        prioridad=$(echo "$linea" | awk '{print $1}')
        servidor=$(echo "$linea" | awk '{print $2}')
        L "   ${CYAN}$(printf '%-12s' "$prioridad")${NC} ${CYAN}${servidor}${NC}"
        MX_SERVERS+=("$servidor")
    done <<< "$mx"

    sumar_puntos 2 2

    LV
    L " Proveedor detectado: \c"

    # --- Proveedores principales ---
    if echo "$mx" | grep -qi "google\|gmail\|googlemail"; then
        printf "${GREEN}Google Workspace${NC}\n"
    elif echo "$mx" | grep -qi "outlook\|microsoft"; then
        printf "${GREEN}Microsoft 365${NC}\n"
    elif echo "$mx" | grep -qi "protonmail\|proton"; then
        printf "${GREEN}ProtonMail${NC}\n"
    elif echo "$mx" | grep -qi "zoho"; then
        printf "${GREEN}Zoho Mail${NC}\n"
    elif echo "$mx" | grep -qi "yahoo\|yahoodns"; then
        printf "${GREEN}Yahoo Mail${NC}\n"
    elif echo "$mx" | grep -qi "icloud\|apple\|me\.com"; then
        printf "${GREEN}Apple iCloud Mail${NC}\n"
    elif echo "$mx" | grep -qi "yandex"; then
        printf "${GREEN}Yandex Mail${NC}\n"
    elif echo "$mx" | grep -qi "fastmail"; then
        printf "${GREEN}Fastmail${NC}\n"
    elif echo "$mx" | grep -qi "tutanota\|tuta\.io"; then
        printf "${GREEN}Tuta (Tutanota)${NC}\n"
    elif echo "$mx" | grep -qi "mailfence"; then
        printf "${GREEN}Mailfence${NC}\n"
    elif echo "$mx" | grep -qi "migadu"; then
        printf "${GREEN}Migadu${NC}\n"

    # --- Gateways de seguridad / antispam ---
    elif echo "$mx" | grep -qi "mimecast"; then
        printf "${GREEN}Mimecast${NC}\n"
    elif echo "$mx" | grep -qi "barracuda"; then
        printf "${GREEN}Barracuda${NC}\n"
    elif echo "$mx" | grep -qi "pphosted\|proofpoint"; then
        printf "${GREEN}Proofpoint${NC}\n"
    elif echo "$mx" | grep -qi "messagelabs\|symantec\.email\|broadcom"; then
        printf "${GREEN}Symantec/Broadcom Email Security${NC}\n"
    elif echo "$mx" | grep -qi "trendmicro\|in\.hes\.trendmicro"; then
        printf "${GREEN}Trend Micro Email Security${NC}\n"
    elif echo "$mx" | grep -qi "sophos\|reflexion"; then
        printf "${GREEN}Sophos Email${NC}\n"
    elif echo "$mx" | grep -qi "forcepoint\|mailcontrol"; then
        printf "${GREEN}Forcepoint${NC}\n"
    elif echo "$mx" | grep -qi "cisco\|ironport\|iphmx"; then
        printf "${GREEN}Cisco Secure Email (IronPort)${NC}\n"
    elif echo "$mx" | grep -qi "fireeye\|trellix"; then
        printf "${GREEN}Trellix (FireEye) Email Security${NC}\n"
    elif echo "$mx" | grep -qi "spamexperts\|antispamcloud"; then
        printf "${GREEN}SpamExperts${NC}\n"
    elif echo "$mx" | grep -qi "hornetsecurity\|hornetdrive"; then
        printf "${GREEN}Hornetsecurity${NC}\n"
    elif echo "$mx" | grep -qi "cloudflare"; then
        printf "${GREEN}Cloudflare Email Routing${NC}\n"

    # --- Plataformas de envío transaccional / marketing ---
    elif echo "$mx" | grep -qi "mailgun"; then
        printf "${GREEN}Mailgun${NC}\n"
    elif echo "$mx" | grep -qi "sendgrid"; then
        printf "${GREEN}SendGrid (Twilio)${NC}\n"
    elif echo "$mx" | grep -qi "amazonses\|amazonaws"; then
        printf "${GREEN}Amazon SES${NC}\n"
    elif echo "$mx" | grep -qi "postmarkapp"; then
        printf "${GREEN}Postmark${NC}\n"
    elif echo "$mx" | grep -qi "mailchimp\|mandrillapp"; then
        printf "${GREEN}Mailchimp / Mandrill${NC}\n"
    elif echo "$mx" | grep -qi "mailjet"; then
        printf "${GREEN}Mailjet${NC}\n"

    # --- Hosting / registradores ---
    elif echo "$mx" | grep -qi "ovh"; then
        printf "${GREEN}OVH${NC}\n"
    elif echo "$mx" | grep -qi "ionos\|1and1\|perfora\|kundenserver"; then
        printf "${GREEN}IONOS (1&1)${NC}\n"
    elif echo "$mx" | grep -qi "gandi"; then
        printf "${GREEN}Gandi${NC}\n"
    elif echo "$mx" | grep -qi "hover"; then
        printf "${GREEN}Hover${NC}\n"
    elif echo "$mx" | grep -qi "namecheap\|privateemail"; then
        printf "${GREEN}Namecheap (Private Email)${NC}\n"
    elif echo "$mx" | grep -qi "godaddy\|secureserver"; then
        printf "${GREEN}GoDaddy${NC}\n"
    elif echo "$mx" | grep -qi "rackspace\|emailsrvr"; then
        printf "${GREEN}Rackspace Email${NC}\n"
    elif echo "$mx" | grep -qi "hostgator\|websitewelcome"; then
        printf "${GREEN}HostGator${NC}\n"
    elif echo "$mx" | grep -qi "bluehost"; then
        printf "${GREEN}Bluehost${NC}\n"
    elif echo "$mx" | grep -qi "dreamhost"; then
        printf "${GREEN}DreamHost${NC}\n"
    elif echo "$mx" | grep -qi "hetzner"; then
        printf "${GREEN}Hetzner${NC}\n"
    elif echo "$mx" | grep -qi "strato"; then
        printf "${GREEN}Strato${NC}\n"
    elif echo "$mx" | grep -qi "arsys\|nicline"; then
        printf "${GREEN}Arsys${NC}\n"
    elif echo "$mx" | grep -qi "dinahosting"; then
        printf "${GREEN}Dinahosting${NC}\n"

    # --- Paneles de control / plataformas colaborativas ---
    elif echo "$mx" | grep -qi "cpanel\|whm"; then
        printf "${GREEN}cPanel Mail${NC}\n"
    elif echo "$mx" | grep -qi "plesk"; then
        printf "${GREEN}Plesk Mail${NC}\n"
    elif echo "$mx" | grep -qi "zimbra"; then
        printf "${GREEN}Zimbra${NC}\n"

    # --- No identificado ---
    else
        local mx_host
        mx_host=$(echo "$mx" | head -1 | awk '{print $2}')
        printf "${YELLOW}No identificado${NC} (${DIM}${mx_host}${NC})\n"
    fi
    seccion_fin
}

# ═════════════════════════════════════════════════════════════════════
# 2. SPF
# ═════════════════════════════════════════════════════════════════════
auditar_spf() {
    local dominio="$1"
    seccion_inicio
    L "${BOLD}2. SPF (Sender Policy Framework)${NC}"
    L "${DIM}Define qué servidores IP tienen permiso para enviar correo en${NC}"
    L "${DIM}nombre de este dominio. Sin SPF, cualquier servidor podría${NC}"
    L "${DIM}enviar correo suplantando la identidad (spoofing). RFC 7208.${NC}"
    LV

    local spf
    spf=$(safe_dig +short TXT "$dominio" | grep -i "v=spf1" || true)

    if [[ -z "$spf" ]]; then
        L " ${FAIL} No se encontró registro SPF"
        L "   ${YELLOW}→ Vulnerable a spoofing${NC}"
        sumar_puntos 0 3
        seccion_fin
        return
    fi

    L " ${OK} Registro encontrado:"
    L "   ${CYAN}${spf}${NC}"
    LV

    # redirect=
    local tiene_redirect=""
    tiene_redirect=$(echo "$spf" | grep -oP 'redirect=\K[^ "]+' || true)

    if [[ -n "$tiene_redirect" ]]; then
        L " ${INFO} Usa ${CYAN}redirect=${tiene_redirect}${NC}"

        local spf_redir
        spf_redir=$(safe_dig +short TXT "$tiene_redirect" | grep -i "v=spf1" || true)
        if [[ -n "$spf_redir" ]]; then
            local spf_redir_limpio
            spf_redir_limpio=$(printf '%s' "$spf_redir" | tr -d '"')
            if [[ ${#spf_redir_limpio} -gt 70 ]]; then
                spf_redir_limpio="${spf_redir_limpio:0:67}..."
            fi
            L "   SPF delegado: ${DIM}${spf_redir_limpio}${NC}"

            if echo "$spf_redir" | grep -q "\-all"; then
                L " ${OK} Política heredada: ${GREEN}ESTRICTA (-all)${NC}"
                sumar_puntos 3 3
            elif echo "$spf_redir" | grep -q "\~all"; then
                L " ${WARN} Política heredada: ${YELLOW}SUAVE (~all)${NC}"
                sumar_puntos 2 3
            else
                L " ${WARN} Política heredada no determinada claramente"
                sumar_puntos 1 3
            fi
        else
            L " ${WARN} No se pudo resolver el SPF del dominio redirect"
            sumar_puntos 1 3
        fi
    elif echo "$spf" | grep -q "\-all"; then
        L " ${OK} Política: ${GREEN}ESTRICTA (-all)${NC} — rechaza correo no autorizado"
        sumar_puntos 3 3
    elif echo "$spf" | grep -q "\~all"; then
        L " ${WARN} Política: ${YELLOW}SUAVE (~all)${NC} — marca como sospechoso, no rechaza"
        sumar_puntos 2 3
    elif echo "$spf" | grep -q "\?all"; then
        L " ${WARN} Política: ${YELLOW}NEUTRAL (?all)${NC} — sin acción"
        sumar_puntos 1 3
    elif echo "$spf" | grep -q "+all"; then
        L " ${FAIL} Política: ${RED}ABIERTA (+all)${NC} — ¡cualquiera puede suplantar!"
        sumar_puntos 0 3
    else
        L " ${WARN} No se detectó mecanismo 'all' explícito"
        sumar_puntos 1 3
    fi

    local lookups
    lookups=$(echo "$spf" | grep -oE '(include:|a:|mx:|ptr:|redirect=)' | wc -l | tr -d ' ')
    if [[ "$lookups" -gt 10 ]]; then
        L " ${FAIL} DNS lookups: ${RED}${lookups}/10${NC} — excede RFC 7208"
    elif [[ "$lookups" -gt 7 ]]; then
        L " ${WARN} DNS lookups: ${YELLOW}${lookups}/10${NC} — cerca del límite"
    else
        L " ${OK} DNS lookups: ${GREEN}${lookups}/10${NC}"
    fi
    seccion_fin
}

# ═════════════════════════════════════════════════════════════════════
# 3. DKIM
# ═════════════════════════════════════════════════════════════════════
auditar_dkim() {
    local dominio="$1"
    seccion_inicio
    L "${BOLD}3. DKIM (DomainKeys Identified Mail)${NC}"
    L "${DIM}Firma criptográfica en cabeceras del mensaje que permite al${NC}"
    L "${DIM}receptor verificar que el correo no fue alterado en tránsito${NC}"
    L "${DIM}y que realmente proviene del dominio firmante. RFC 6376.${NC}"
    LV

    local selectores=("default" "google" "selector1" "selector2" "k1" "k2"
                      "mail" "dkim" "s1" "s2" "smtp" "mandrill" "everlytickey1"
                      "mxvault" "cm" "protonmail" "protonmail2" "protonmail3"
                      "20230601" "20221208" "20210112" "20161025"
                      "sig1" "m1" "smtp2" "email" "mkto" "aweber" "constantcontact"
                      "zohocorp" "zendesk1" "zendesk2" "ovh" "mailjet" "mg" "krs" "mailo"
                      "pic" "intercom" "hs1" "hs2" "dk" "kl" "neolane" "mta" "mindbox"
                      "sailthru" "qualtrics" "fnc" "firebase1")

    local encontrados=0

    for selector in "${selectores[@]}"; do
        local resultado
        resultado=$(safe_dig +short TXT "${selector}._domainkey.${dominio}" || true)
        if [[ -n "$resultado" ]] && echo "$resultado" | grep -qi "p="; then
            if [[ $encontrados -eq 0 ]]; then
                L " ${OK} Registros DKIM encontrados:"
            fi
            L "   Selector: ${CYAN}$(printf '%-15s' "$selector")${NC} → ${GREEN}Presente${NC}"
            encontrados=$((encontrados + 1))
        fi
    done

    if [[ $encontrados -eq 0 ]]; then
        L " ${WARN} Sin registros DKIM en selectores comunes"
        L "   ${YELLOW}→ Puede usar un selector personalizado no probado${NC}"
        L "   ${DIM}Prueba manual: dig TXT <selector>._domainkey.${dominio}${NC}"
        sumar_puntos 0 2
    else
        L " ${OK} Total: ${GREEN}${encontrados}${NC} selector(es) DKIM verificados"
        sumar_puntos 2 2
    fi
    seccion_fin
}

# ═════════════════════════════════════════════════════════════════════
# 4. DMARC
# ═════════════════════════════════════════════════════════════════════
auditar_dmarc() {
    local dominio="$1"
    seccion_inicio
    L "${BOLD}4. DMARC (Domain-based Message Authentication, Reporting & Conformance)${NC}"
    L "${DIM}Política que une SPF y DKIM: indica a los receptores qué hacer${NC}"
    L "${DIM}cuando un mensaje falla la autenticación (rechazar, cuarentena${NC}"
    L "${DIM}o solo monitorizar). También permite recibir reportes. RFC 7489.${NC}"
    LV

    local dmarc_raw
    dmarc_raw=$(safe_dig +noall +answer TXT "_dmarc.${dominio}" || true)

    local dmarc
    dmarc=$(echo "$dmarc_raw" | grep -oP '"v=DMARC1[^"]*"' | head -1 || true)

    if [[ -z "$dmarc" ]]; then
        L " ${FAIL} No se encontró registro DMARC"
        L "   ${YELLOW}→ Sin instrucciones para correo no autenticado${NC}"
        sumar_puntos 0 3
        seccion_fin
        return
    fi

    local cname_target
    cname_target=$(echo "$dmarc_raw" | awk '/CNAME/{print $NF}' | head -1 || true)

    L " ${OK} Registro encontrado:"
    if [[ -n "$cname_target" ]]; then
        L "   ${DIM}(delegado vía CNAME → ${cname_target})${NC}"
    fi
    L "   ${CYAN}${dmarc}${NC}"
    LV

    local politica
    politica=$(echo "$dmarc" | grep -oP 'p=\K[^;]+' | tr -d '"' | head -1 || true)
    case "$politica" in
        reject)
            L " ${OK} Política: ${GREEN}REJECT${NC} — rechaza correo no autenticado"
            sumar_puntos 3 3
            ;;
        quarantine)
            L " ${WARN} Política: ${YELLOW}QUARANTINE${NC} — envía a spam"
            sumar_puntos 2 3
            ;;
        none)
            L " ${WARN} Política: ${YELLOW}NONE${NC} — solo monitoriza, sin protección activa"
            sumar_puntos 1 3
            ;;
        *)
            L " ${WARN} Política no reconocida: '${politica}'"
            sumar_puntos 0 3
            ;;
    esac

    local sub_politica
    sub_politica=$(echo "$dmarc" | grep -oP 'sp=\K[^;]+' | tr -d '"' | head -1 || true)
    if [[ -n "$sub_politica" ]]; then
        L "   Subdominios (sp): ${CYAN}${sub_politica}${NC}"
    fi

    local pct
    pct=$(echo "$dmarc" | grep -oP 'pct=\K[0-9]+' | head -1 || true)
    if [[ -n "$pct" ]] && [[ "$pct" -lt 100 ]]; then
        L " ${WARN} Aplicado solo al ${YELLOW}${pct}%%${NC} del correo (objetivo: 100%%)"
    fi

    local rua ruf
    rua=$(echo "$dmarc" | grep -oP 'rua=\K[^;]+' | tr -d '"' | head -1 || true)
    ruf=$(echo "$dmarc" | grep -oP 'ruf=\K[^;]+' | tr -d '"' | head -1 || true)
    LV
    L " Reportes:"
    if [[ -n "$rua" ]]; then
        L "   ${OK} Agregados (rua): ${CYAN}${rua}${NC}"
    else
        L "   ${WARN} Sin reportes agregados (rua)"
    fi
    if [[ -n "$ruf" ]]; then
        L "   ${OK} Forenses  (ruf): ${CYAN}${ruf}${NC}"
    else
        L "   ${INFO} Sin reportes forenses (ruf) — opcional"
    fi
    seccion_fin
}

# ═════════════════════════════════════════════════════════════════════
# 5. DANE / TLSA
# ═════════════════════════════════════════════════════════════════════
auditar_dane() {
    local dominio="$1"
    seccion_inicio
    L "${BOLD}5. DANE/TLSA (DNS-based Authentication of Named Entities)${NC}"
    L "${DIM}Vincula certificados TLS directamente a registros DNS, evitando${NC}"
    L "${DIM}depender únicamente de CAs. Requiere DNSSEC para garantizar${NC}"
    L "${DIM}la integridad de los registros TLSA. RFC 6698 / RFC 7672.${NC}"
    LV

    local dnssec_ok=false
    local dnssec_check
    dnssec_check=$(safe_dig +dnssec +short DNSKEY "$dominio" || true)

    if [[ -n "$dnssec_check" ]]; then
        local ad_check
        ad_check=$(safe_dig +dnssec "$dominio" A | grep -c "flags:.*ad" || true)
        if [[ "$ad_check" -gt 0 ]]; then
            L " ${OK} DNSSEC: ${GREEN}Validado (flag AD presente)${NC}"
            dnssec_ok=true
        else
            L " ${WARN} DNSSEC: ${YELLOW}DNSKEY encontrado, sin validación AD${NC}"
            L "   ${DIM}Puede depender del resolver utilizado${NC}"
            dnssec_ok=true
        fi
    else
        L " ${FAIL} DNSSEC: ${RED}No habilitado${NC}"
        L "   ${YELLOW}→ DANE requiere DNSSEC para funcionar${NC}"
    fi

    LV

    if [[ ${#MX_SERVERS[@]} -eq 0 ]]; then
        L " ${WARN} Sin servidores MX — no se puede verificar TLSA"
        sumar_puntos 0 2
        seccion_fin
        return
    fi

    local tlsa_encontrados=0
    local tlsa_total=0
    local starttls_count=0

    L " Registros TLSA (puerto 25/SMTP) por servidor MX:"
    LV

    for mx_server in "${MX_SERVERS[@]}"; do
        mx_server="${mx_server%.}"
        tlsa_total=$((tlsa_total + 1))

        local tlsa
        tlsa=$(safe_dig +short TLSA "_25._tcp.${mx_server}" || true)

        if [[ -n "$tlsa" ]]; then
            tlsa_encontrados=$((tlsa_encontrados + 1))
            L "   ${OK} ${CYAN}${mx_server}${NC}"

            while IFS= read -r registro; do
                [[ -z "$registro" ]] && continue
                local usage selector matching
                usage=$(echo "$registro" | awk '{print $1}')
                selector=$(echo "$registro" | awk '{print $2}')
                matching=$(echo "$registro" | awk '{print $3}')

                local uso_desc
                case "$usage" in
                    0) uso_desc="CA constraint (PKIX-TA)" ;;
                    1) uso_desc="Service cert (PKIX-EE)" ;;
                    2) uso_desc="Trust anchor (DANE-TA)" ;;
                    3) uso_desc="Domain cert (DANE-EE)" ;;
                    *) uso_desc="Desconocido" ;;
                esac

                local sel_desc
                case "$selector" in
                    0) sel_desc="Cert completo" ;;
                    1) sel_desc="Clave pública" ;;
                    *) sel_desc="Desconocido" ;;
                esac

                local match_desc
                case "$matching" in
                    0) match_desc="Exact" ;;
                    1) match_desc="SHA-256" ;;
                    2) match_desc="SHA-512" ;;
                    *) match_desc="Desconocido" ;;
                esac

                L "      Uso: ${GREEN}${usage}${NC} (${uso_desc})"
                L "      Selector: ${selector} (${sel_desc}) · Match: ${matching} (${match_desc})"
            done <<< "$tlsa"
        else
            L "   ${FAIL} ${CYAN}${mx_server}${NC} → Sin TLSA"
        fi

        # STARTTLS básico con nc (fallback si no hay openssl)
        if command -v timeout &>/dev/null && command -v nc &>/dev/null; then
            local smtp_banner
            smtp_banner=$(timeout 5 bash -c "echo 'EHLO test' | nc -w3 \"${mx_server}\" 25" 2>/dev/null || true)
            if [[ -n "$smtp_banner" ]] && echo "$smtp_banner" | grep -qi "STARTTLS"; then
                L "      ${OK} STARTTLS: ${GREEN}Soportado${NC}"
                starttls_count=$((starttls_count + 1))
            elif [[ -n "$smtp_banner" ]]; then
                L "      ${WARN} STARTTLS: ${YELLOW}No anunciado en EHLO${NC}"
            else
                L "      ${INFO} STARTTLS: ${DIM}Sin respuesta en puerto 25${NC}"
            fi
        fi
        LV
    done

    L " Resumen DANE/TLSA:"
    if [[ $tlsa_encontrados -gt 0 ]] && [[ "$dnssec_ok" == true ]]; then
        L "   ${OK} ${GREEN}${tlsa_encontrados}/${tlsa_total}${NC} servidores MX con TLSA"
        if [[ $tlsa_encontrados -eq $tlsa_total ]]; then
            sumar_puntos 2 2
        else
            sumar_puntos 1 2
        fi
    elif [[ $tlsa_encontrados -gt 0 ]]; then
        L "   ${WARN} TLSA encontrados pero ${YELLOW}DNSSEC no validado${NC}"
        sumar_puntos 1 2
    else
        L "   ${FAIL} Sin registros TLSA en ningún servidor MX"
        if [[ "$dnssec_ok" == true ]]; then
            L "   ${YELLOW}→ DNSSEC activo: buen momento para implementar DANE${NC}"
        else
            L "   ${YELLOW}→ Habilitar DNSSEC primero, luego añadir TLSA${NC}"
        fi
        sumar_puntos 0 2
    fi

    if [[ $starttls_count -gt 0 ]]; then
        L "   ${OK} STARTTLS verificado en ${GREEN}${starttls_count}${NC} servidor(es)"
    fi
    seccion_fin
}

# ═════════════════════════════════════════════════════════════════════
# 6. MTA-STS (SMTP MTA Strict Transport Security)
# ═════════════════════════════════════════════════════════════════════
auditar_mta_sts() {
    local dominio="$1"
    seccion_inicio
    L "${BOLD}6. MTA-STS (SMTP MTA Strict Transport Security)${NC}"
    L "${DIM}Permite al dominio declarar que sus servidores MX soportan TLS${NC}"
    L "${DIM}y que los remitentes deben rechazar la entrega si no se puede${NC}"
    L "${DIM}establecer una conexión TLS segura. Complementa DANE sin${NC}"
    L "${DIM}requerir DNSSEC. RFC 8461.${NC}"
    LV

    # Paso 1: registro DNS TXT en _mta-sts.dominio
    local mta_sts_dns
    mta_sts_dns=$(safe_dig +short TXT "_mta-sts.${dominio}" | tr -d '"' || true)

    if [[ -z "$mta_sts_dns" ]]; then
        L " ${FAIL} No se encontró registro DNS para MTA-STS"
        L "   ${DIM}_mta-sts.${dominio} TXT → (vacío)${NC}"
        L "   ${YELLOW}→ Sin protección contra downgrade de TLS en SMTP${NC}"
        sumar_puntos 0 2
        seccion_fin
        return
    fi

    if ! echo "$mta_sts_dns" | grep -qi "v=STSv1"; then
        L " ${WARN} Registro TXT encontrado pero no contiene v=STSv1"
        L "   ${CYAN}${mta_sts_dns}${NC}"
        sumar_puntos 0 2
        seccion_fin
        return
    fi

    L " ${OK} Registro DNS encontrado:"
    L "   ${CYAN}${mta_sts_dns}${NC}"

    # Extraer id de la política
    local sts_id
    sts_id=$(echo "$mta_sts_dns" | grep -oP 'id=\K[^;[:space:]]+' || true)
    if [[ -n "$sts_id" ]]; then
        L "   ID de política: ${CYAN}${sts_id}${NC}"
    fi

    LV

    # Paso 2: descargar política real vía HTTPS (requiere curl)
    if [[ "$TIENE_CURL" == true ]]; then
        L " Descargando política desde HTTPS..."
        local policy_url="https://mta-sts.${dominio}/.well-known/mta-sts.txt"
        local policy
        policy=$(curl -sS --max-time 10 --location "$policy_url" 2>/dev/null || true)

        if [[ -z "$policy" ]]; then
            L "   ${WARN} No se pudo descargar ${DIM}${policy_url}${NC}"
            L "   ${YELLOW}→ El registro DNS existe pero la política no es accesible${NC}"
            L "   ${YELLOW}→ Verificar que mta-sts.${dominio} resuelve y tiene HTTPS${NC}"
            sumar_puntos 1 2
        else
            L "   ${OK} Política descargada correctamente:"
            LV

            # Parsear campos de la política
            local mode max_age mx_lines
            mode=$(echo "$policy" | grep -oP 'mode:\s*\K\S+' | head -1 || true)
            max_age=$(echo "$policy" | grep -oP 'max_age:\s*\K[0-9]+' | head -1 || true)
            mx_lines=$(echo "$policy" | grep -oP 'mx:\s*\K\S+' || true)

            if [[ -n "$mode" ]]; then
                case "$mode" in
                    enforce)
                        L "   ${OK} Modo: ${GREEN}ENFORCE${NC} — rechaza entrega sin TLS válido"
                        ;;
                    testing)
                        L "   ${WARN} Modo: ${YELLOW}TESTING${NC} — reporta fallos pero entrega igualmente"
                        ;;
                    none)
                        L "   ${WARN} Modo: ${YELLOW}NONE${NC} — desactiva la política"
                        ;;
                    *)
                        L "   ${WARN} Modo: ${YELLOW}${mode}${NC} — no reconocido"
                        ;;
                esac
            fi

            if [[ -n "$max_age" ]]; then
                local dias=$((max_age / 86400))
                L "   Vigencia (max_age): ${CYAN}${max_age}s${NC} (~${dias} días)"
                if [[ $max_age -lt 86400 ]]; then
                    L "   ${WARN} max_age muy bajo (<1 día). Recomendado: ≥604800 (1 semana)"
                fi
            fi

            if [[ -n "$mx_lines" ]]; then
                L "   Servidores MX autorizados:"
                while IFS= read -r mx_entry; do
                    [[ -z "$mx_entry" ]] && continue
                    L "      ${CYAN}${mx_entry}${NC}"
                done <<< "$mx_lines"
            fi

            if [[ "$mode" == "enforce" ]]; then
                sumar_puntos 2 2
            elif [[ "$mode" == "testing" ]]; then
                sumar_puntos 1 2
            else
                sumar_puntos 0 2
            fi
        fi
    else
        L "   ${INFO} ${DIM}Instalar 'curl' para verificar la política HTTPS completa${NC}"
        L "   ${DIM}Solo se verificó el registro DNS (paso 1 de 2)${NC}"
        sumar_puntos 1 2
    fi
    seccion_fin
}

# ═════════════════════════════════════════════════════════════════════
# 7. TLS-RPT (SMTP TLS Reporting)
# ═════════════════════════════════════════════════════════════════════
auditar_tls_rpt() {
    local dominio="$1"
    seccion_inicio
    L "${BOLD}7. TLS-RPT (SMTP TLS Reporting)${NC}"
    L "${DIM}Permite recibir reportes cuando otros servidores tienen problemas${NC}"
    L "${DIM}al establecer conexiones TLS con tus MX. Esencial para detectar${NC}"
    L "${DIM}fallos de MTA-STS o DANE. Sin TLS-RPT los fallos son invisibles.${NC}"
    L "${DIM}RFC 8460.${NC}"
    LV

    local tlsrpt
    tlsrpt=$(safe_dig +short TXT "_smtp._tls.${dominio}" | tr -d '"' || true)

    if [[ -z "$tlsrpt" ]]; then
        L " ${FAIL} No se encontró registro TLS-RPT"
        L "   ${DIM}_smtp._tls.${dominio} TXT → (vacío)${NC}"
        L "   ${YELLOW}→ No recibirás reportes de fallos TLS de otros servidores${NC}"
        sumar_puntos 0 1
        seccion_fin
        return
    fi

    if ! echo "$tlsrpt" | grep -qi "v=TLSRPTv1"; then
        L " ${WARN} Registro TXT encontrado pero no contiene v=TLSRPTv1"
        L "   ${CYAN}${tlsrpt}${NC}"
        sumar_puntos 0 1
        seccion_fin
        return
    fi

    L " ${OK} Registro encontrado:"
    L "   ${CYAN}${tlsrpt}${NC}"

    # Extraer destinos de reporte
    local rua
    rua=$(echo "$tlsrpt" | grep -oP 'rua=\K[^;]+' || true)
    if [[ -n "$rua" ]]; then
        LV
        L " Destinos de reporte:"
        # Separar por comas si hay múltiples
        IFS=',' read -ra destinos <<< "$rua"
        for dest in "${destinos[@]}"; do
            dest=$(echo "$dest" | xargs)  # trim espacios
            if echo "$dest" | grep -q "mailto:"; then
                L "   ${OK} Email: ${CYAN}${dest}${NC}"
            elif echo "$dest" | grep -q "https:"; then
                L "   ${OK} HTTPS: ${CYAN}${dest}${NC}"
            else
                L "   ${INFO} ${CYAN}${dest}${NC}"
            fi
        done
    fi

    sumar_puntos 1 1
    seccion_fin
}

# ═════════════════════════════════════════════════════════════════════
# 8. BIMI (Brand Indicators for Message Identification)
# ═════════════════════════════════════════════════════════════════════
auditar_bimi() {
    local dominio="$1"
    seccion_inicio
    L "${BOLD}8. BIMI (Brand Indicators for Message Identification)${NC}"
    L "${DIM}Permite mostrar el logotipo de la marca junto al remitente en${NC}"
    L "${DIM}bandejas de entrada compatibles (Gmail, Yahoo, Apple Mail...).${NC}"
    L "${DIM}Requiere DMARC con p=quarantine o p=reject. Opcionalmente se${NC}"
    L "${DIM}puede incluir un VMC (Verified Mark Certificate) para mayor${NC}"
    L "${DIM}confianza. RFC pendiente (draft adoptado por múltiples ISPs).${NC}"
    LV

    local bimi
    bimi=$(safe_dig +short TXT "default._bimi.${dominio}" | tr -d '"' || true)

    if [[ -z "$bimi" ]]; then
        L " ${INFO} No se encontró registro BIMI"
        L "   ${DIM}default._bimi.${dominio} TXT → (vacío)${NC}"
        L "   ${DIM}→ Opcional pero recomendado si DMARC está en enforce/quarantine${NC}"
        sumar_puntos 0 1
        seccion_fin
        return
    fi

    if ! echo "$bimi" | grep -qi "v=BIMI1"; then
        L " ${WARN} Registro TXT encontrado pero no contiene v=BIMI1"
        L "   ${CYAN}${bimi}${NC}"
        sumar_puntos 0 1
        seccion_fin
        return
    fi

    L " ${OK} Registro BIMI encontrado:"
    L "   ${CYAN}${bimi}${NC}"
    LV

    # Extraer URL del logo
    local logo_url
    logo_url=$(echo "$bimi" | grep -oP 'l=\K[^;]+' || true)
    if [[ -n "$logo_url" ]]; then
        L "   Logo (SVG): ${CYAN}${logo_url}${NC}"

        # Verificar accesibilidad del logo si hay curl
        if [[ "$TIENE_CURL" == true ]]; then
            local http_code
            http_code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "$logo_url" 2>/dev/null || echo "000")
            if [[ "$http_code" == "200" ]]; then
                L "   ${OK} Logo accesible (HTTP ${GREEN}${http_code}${NC})"
            else
                L "   ${WARN} Logo no accesible (HTTP ${YELLOW}${http_code}${NC})"
            fi
        fi
    else
        L "   ${WARN} No se encontró URL del logo (parámetro l=)"
    fi

    # Extraer VMC (Verified Mark Certificate)
    local vmc_url
    vmc_url=$(echo "$bimi" | grep -oP 'a=\K[^;]+' || true)
    if [[ -n "$vmc_url" ]]; then
        L "   VMC: ${CYAN}${vmc_url}${NC}"
        L "   ${OK} Certificado de marca verificada presente"
    else
        L "   ${INFO} Sin VMC (a=) — el logo puede no mostrarse en todos los clientes"
    fi

    sumar_puntos 1 1
    seccion_fin
}

# ═════════════════════════════════════════════════════════════════════
# 9. Certificados TLS de servidores MX (requiere openssl)
# ═════════════════════════════════════════════════════════════════════
auditar_tls_certs() {
    local dominio="$1"
    seccion_inicio
    L "${BOLD}9. Certificados TLS de servidores MX${NC}"
    L "${DIM}Verifica el certificado TLS que presenta cada servidor MX al${NC}"
    L "${DIM}negociar STARTTLS en puerto 25. Un certificado caducado, auto-${NC}"
    L "${DIM}firmado o que no coincide con el hostname permite ataques MitM.${NC}"
    LV

    if [[ "$TIENE_OPENSSL" != true ]]; then
        L " ${INFO} ${DIM}openssl no disponible — se omite la verificación de certificados${NC}"
        L "   ${DIM}Instalar con: apt install openssl / brew install openssl${NC}"
        seccion_fin
        return
    fi

    if [[ ${#MX_SERVERS[@]} -eq 0 ]]; then
        L " ${WARN} Sin servidores MX — nada que verificar"
        seccion_fin
        return
    fi

    local certs_ok=0
    local certs_total=0

    for mx_server in "${MX_SERVERS[@]}"; do
        mx_server="${mx_server%.}"
        certs_total=$((certs_total + 1))

        L "   ${CYAN}${mx_server}${NC}"

        # Obtener certificado vía STARTTLS
        local cert_info
        cert_info=$(echo "" | timeout 10 openssl s_client \
            -starttls smtp \
            -connect "${mx_server}:25" \
            -servername "${mx_server}" \
            2>/dev/null || true)

        if [[ -z "$cert_info" ]] || ! echo "$cert_info" | grep -q "BEGIN CERTIFICATE"; then
            L "      ${FAIL} No se pudo obtener certificado TLS"
            L "      ${YELLOW}→ STARTTLS no disponible o conexión rechazada${NC}"
            LV
            continue
        fi

        # Extraer subject y emisor
        local subject issuer
        subject=$(echo "$cert_info" | openssl x509 -noout -subject 2>/dev/null | sed 's/subject=//' || true)
        issuer=$(echo "$cert_info" | openssl x509 -noout -issuer 2>/dev/null | sed 's/issuer=//' || true)

        # SANs (Subject Alternative Names)
        local sans
        sans=$(echo "$cert_info" | openssl x509 -noout -ext subjectAltName 2>/dev/null | grep -oP 'DNS:\K[^,]+' | tr '\n' ' ' || true)

        # Fechas de validez
        local not_before not_after
        not_before=$(echo "$cert_info" | openssl x509 -noout -startdate 2>/dev/null | sed 's/notBefore=//' || true)
        not_after=$(echo "$cert_info" | openssl x509 -noout -enddate 2>/dev/null | sed 's/notAfter=//' || true)

        # Protocolo TLS negociado
        local tls_version
        tls_version=$(echo "$cert_info" | grep -oP 'Protocol\s*:\s*\K\S+' | head -1 || true)

        # Mostrar info
        if [[ -n "$subject" ]]; then
            L "      Subject: ${DIM}${subject}${NC}"
        fi
        if [[ -n "$issuer" ]]; then
            # Extraer solo el CN/O del emisor para brevedad
            local issuer_short
            issuer_short=$(echo "$issuer" | grep -oP 'O\s*=\s*\K[^/,]+' | head -1 || echo "$issuer")
            L "      Emisor:  ${DIM}${issuer_short}${NC}"
        fi
        if [[ -n "$tls_version" ]]; then
            if [[ "$tls_version" == "TLSv1.3" ]]; then
                L "      TLS:     ${GREEN}${tls_version}${NC}"
            elif [[ "$tls_version" == "TLSv1.2" ]]; then
                L "      TLS:     ${GREEN}${tls_version}${NC}"
            elif [[ "$tls_version" == "TLSv1.1" ]] || [[ "$tls_version" == "TLSv1" ]]; then
                L "      TLS:     ${RED}${tls_version}${NC} — obsoleto e inseguro"
            else
                L "      TLS:     ${YELLOW}${tls_version}${NC}"
            fi
        fi

        # Verificar caducidad
        if [[ -n "$not_after" ]]; then
            local expiry_epoch now_epoch days_left
            expiry_epoch=$(date -d "$not_after" +%s 2>/dev/null || date -jf "%b %d %T %Y %Z" "$not_after" +%s 2>/dev/null || echo "0")
            now_epoch=$(date +%s)

            if [[ "$expiry_epoch" -gt 0 ]]; then
                days_left=$(( (expiry_epoch - now_epoch) / 86400 ))
                if [[ $days_left -lt 0 ]]; then
                    L "      ${FAIL} Certificado ${RED}CADUCADO${NC} hace $(( days_left * -1 )) días"
                elif [[ $days_left -lt 14 ]]; then
                    L "      ${WARN} Caduca en ${RED}${days_left} días${NC} — renovar urgentemente"
                elif [[ $days_left -lt 30 ]]; then
                    L "      ${WARN} Caduca en ${YELLOW}${days_left} días${NC}"
                else
                    L "      ${OK} Válido ${GREEN}${days_left} días${NC} más (hasta ${DIM}${not_after}${NC})"
                    certs_ok=$((certs_ok + 1))
                fi
            else
                L "      ${DIM}Expira: ${not_after}${NC}"
                certs_ok=$((certs_ok + 1))
            fi
        fi

        # Verificar hostname match
        local hostname_ok=false
        if [[ -n "$sans" ]]; then
            for san in $sans; do
                # Coincidencia exacta o wildcard
                if [[ "$mx_server" == "$san" ]]; then
                    hostname_ok=true
                    break
                fi
                # Wildcard: *.example.com coincide con mail.example.com
                if [[ "$san" == \*.* ]]; then
                    local wildcard_domain="${san#\*.}"
                    local mx_domain="${mx_server#*.}"
                    if [[ "$mx_domain" == "$wildcard_domain" ]]; then
                        hostname_ok=true
                        break
                    fi
                fi
            done
        fi

        if [[ "$hostname_ok" == true ]]; then
            L "      ${OK} Hostname coincide con certificado"
        else
            # Comprobar también en subject CN
            local cn
            cn=$(echo "$subject" | grep -oP 'CN\s*=\s*\K[^/,]+' | head -1 || true)
            if [[ "$mx_server" == "$cn" ]] || [[ "$cn" == \*.* && "${mx_server#*.}" == "${cn#\*.}" ]]; then
                L "      ${OK} Hostname coincide con CN del certificado"
            else
                L "      ${WARN} Hostname ${YELLOW}no coincide${NC} con SANs/CN del certificado"
                L "      ${DIM}SANs: ${sans:-ninguno}${NC}"
            fi
        fi

        # Verificar si es autofirmado
        local subject_hash issuer_hash
        subject_hash=$(echo "$cert_info" | openssl x509 -noout -subject_hash 2>/dev/null || true)
        issuer_hash=$(echo "$cert_info" | openssl x509 -noout -issuer_hash 2>/dev/null || true)
        if [[ -n "$subject_hash" ]] && [[ "$subject_hash" == "$issuer_hash" ]]; then
            L "      ${FAIL} Certificado ${RED}AUTOFIRMADO${NC}"
        fi

        LV
    done

    if [[ $certs_total -gt 0 ]]; then
        L " Resumen TLS:"
        L "   ${INFO} ${certs_ok}/${certs_total} certificados válidos y vigentes"
        if [[ $certs_ok -eq $certs_total ]]; then
            sumar_puntos 2 2
        elif [[ $certs_ok -gt 0 ]]; then
            sumar_puntos 1 2
        else
            sumar_puntos 0 2
        fi
    fi
    seccion_fin
}

# ═════════════════════════════════════════════════════════════════════
# 10. Protección de subdominios
# ═════════════════════════════════════════════════════════════════════
auditar_subdominios() {
    local dominio="$1"
    seccion_inicio
    L "${BOLD}10. Protección de subdominios contra spoofing${NC}"
    L "${DIM}Los atacantes pueden suplantar correo desde subdominios como${NC}"
    L "${DIM}mail.dominio.com o smtp.dominio.com si estos no tienen su propio${NC}"
    L "${DIM}SPF restrictivo. Un 'null SPF' (v=spf1 -all) en subdominios que${NC}"
    L "${DIM}no envían correo bloquea este vector de ataque.${NC}"
    LV

    # Subdominios comunes que los atacantes intentan suplantar
    local subdominios=("mail" "smtp" "email" "correo" "webmail"
                       "newsletter" "noreply" "no-reply" "bounce"
                       "marketing" "info" "soporte" "support"
                       "admin" "postmaster" "autoresponder")

    local protegidos=0
    local vulnerables=0
    local total_comprobados=0

    L "   ${DIM}$(printf '%-20s %-12s %s' "SUBDOMINIO" "SPF" "ESTADO")${NC}"
    L "   ${DIM}$(printf '%-20s %-12s %s' "──────────────────" "──────────" "──────────────")${NC}"

    for sub in "${subdominios[@]}"; do
        local fqdn="${sub}.${dominio}"

        # Solo comprobar si el subdominio tiene algún registro DNS (existe)
        local tiene_dns
        tiene_dns=$(safe_dig +short A "$fqdn" || true)
        local tiene_mx_sub
        tiene_mx_sub=$(safe_dig +short MX "$fqdn" || true)

        # Si no tiene ni A ni MX, probablemente no existe, saltar
        if [[ -z "$tiene_dns" ]] && [[ -z "$tiene_mx_sub" ]]; then
            continue
        fi

        total_comprobados=$((total_comprobados + 1))

        local spf_sub
        spf_sub=$(safe_dig +short TXT "$fqdn" | grep -i "v=spf1" | tr -d '"' || true)

        if [[ -z "$spf_sub" ]]; then
            L "   ${YELLOW}$(printf '%-20s' "$sub")${NC} ${DIM}$(printf '%-12s' "(sin SPF)")${NC} ${WARN} Vulnerable"
            vulnerables=$((vulnerables + 1))
        elif echo "$spf_sub" | grep -q "\-all" && ! echo "$spf_sub" | grep -qi "include:\|a:\|mx:\|ip4:\|ip6:"; then
            L "   ${GREEN}$(printf '%-20s' "$sub")${NC} ${DIM}$(printf '%-12s' "null SPF")${NC} ${OK} Protegido"
            protegidos=$((protegidos + 1))
        elif echo "$spf_sub" | grep -q "\-all"; then
            L "   ${GREEN}$(printf '%-20s' "$sub")${NC} ${DIM}$(printf '%-12s' "-all")${NC} ${OK} Restrictivo"
            protegidos=$((protegidos + 1))
        elif echo "$spf_sub" | grep -q "\~all"; then
            L "   ${YELLOW}$(printf '%-20s' "$sub")${NC} ${DIM}$(printf '%-12s' "~all")${NC} ${WARN} Softfail"
            vulnerables=$((vulnerables + 1))
        else
            L "   ${YELLOW}$(printf '%-20s' "$sub")${NC} ${DIM}$(printf '%-12s' "otro")${NC} ${INFO} Revisar"
        fi
    done

    LV

    if [[ $total_comprobados -eq 0 ]]; then
        L " ${INFO} No se encontraron subdominios comunes con registros DNS"
        L "   ${DIM}→ Esto es normal si el dominio no usa subdominios de correo${NC}"
        sumar_puntos 1 1
    elif [[ $vulnerables -eq 0 ]]; then
        L " ${OK} ${GREEN}${protegidos}/${total_comprobados}${NC} subdominios protegidos"
        sumar_puntos 1 1
    else
        L " ${WARN} ${YELLOW}${vulnerables}${NC} subdominio(s) sin protección SPF"
        L "   ${YELLOW}→ Añadir registro: v=spf1 -all${NC}"
        sumar_puntos 0 1
    fi

    # Comprobar también la política sp= en DMARC del dominio raíz
    local dmarc_sp
    dmarc_sp=$(safe_dig +noall +answer TXT "_dmarc.${dominio}" | grep -oP 'sp=\K[^;]+' | tr -d '"' | head -1 || true)
    if [[ -n "$dmarc_sp" ]]; then
        LV
        L " ${INFO} DMARC del dominio raíz incluye sp=${CYAN}${dmarc_sp}${NC} para subdominios"
        if [[ "$dmarc_sp" == "reject" ]]; then
            L "   ${OK} Los subdominios heredan política ${GREEN}reject${NC}"
        elif [[ "$dmarc_sp" == "quarantine" ]]; then
            L "   ${WARN} Los subdominios heredan política ${YELLOW}quarantine${NC}"
        else
            L "   ${WARN} Los subdominios heredan política ${YELLOW}${dmarc_sp}${NC}"
        fi
    fi
    seccion_fin
}

# ─── Aviso sin correo ────────────────────────────────────────────────
mostrar_aviso_sin_correo() {
    local dominio="$1"
    printf "\n"
    printf "${YELLOW}╔══════════════════════════════════════════════════════════════╗${NC}\n"
    printf "${YELLOW}║${NC}                                                              ${YELLOW}║${NC}\n"
    printf "${YELLOW}║${NC}  ${WARN} ${BOLD}Este dominio no parece tener correo electrónico configurado${NC} ${YELLOW}║${NC}\n"
    printf "${YELLOW}║${NC}                                                              ${YELLOW}║${NC}\n"
    printf "${YELLOW}║${NC}  No se encontraron registros MX para ${CYAN}${dominio}${NC}               ${YELLOW}║${NC}\n"
    printf "${YELLOW}║${NC}                                                              ${YELLOW}║${NC}\n"
    printf "${YELLOW}║${NC}  Posibles causas:                                            ${YELLOW}║${NC}\n"
    printf "${YELLOW}║${NC}    • Error al escribir el dominio                             ${YELLOW}║${NC}\n"
    printf "${YELLOW}║${NC}    • El dominio no usa correo electrónico                     ${YELLOW}║${NC}\n"
    printf "${YELLOW}║${NC}    • Los registros MX aún no se han propagado                 ${YELLOW}║${NC}\n"
    printf "${YELLOW}║${NC}                                                              ${YELLOW}║${NC}\n"
    printf "${YELLOW}╚══════════════════════════════════════════════════════════════╝${NC}\n"
    printf "\n"
    printf "¿Continuar igualmente con la auditoría? [s/N]: "
    local respuesta
    read -r respuesta
    case "$respuesta" in
        [sS]|[sS][iI]|[yY]|[yY][eE][sS])
            return 0
            ;;
        *)
            printf "\nAuditoría cancelada.\n"
            exit 0
            ;;
    esac
}

# ─── Resumen ─────────────────────────────────────────────────────────
mostrar_resumen() {
    local dominio="$1"

    local porcentaje=0
    if [[ $MAX_SCORE -gt 0 ]]; then
        porcentaje=$((SCORE * 100 / MAX_SCORE))
    fi

    local nivel color emoji
    if [[ $porcentaje -ge 80 ]]; then
        nivel="BUENO"
        color="$GREEN"
        emoji="🟢"
    elif [[ $porcentaje -ge 50 ]]; then
        nivel="MEJORABLE"
        color="$YELLOW"
        emoji="🟡"
    else
        nivel="DEFICIENTE"
        color="$RED"
        emoji="🔴"
    fi

    local barra=""
    local llenos=$((porcentaje / 5))
    local vacios=$((20 - llenos))
    for ((i=0; i<llenos; i++)); do barra+="█"; done
    for ((i=0; i<vacios; i++)); do barra+="░"; done

    # Recomendaciones
    local recomendaciones=()

    local spf_check dmarc_check dnssec_present mta_sts_check tlsrpt_check bimi_check
    spf_check=$(safe_dig +short TXT "$dominio" | grep -i "v=spf1" || true)
    dmarc_check=$(safe_dig +noall +answer TXT "_dmarc.${dominio}" | grep -oP '"v=DMARC1[^"]*"' | head -1 || true)
    dnssec_present=$(safe_dig +short DNSKEY "$dominio" || true)
    mta_sts_check=$(safe_dig +short TXT "_mta-sts.${dominio}" | grep -i "STSv1" || true)
    tlsrpt_check=$(safe_dig +short TXT "_smtp._tls.${dominio}" | grep -i "TLSRPTv1" || true)
    bimi_check=$(safe_dig +short TXT "default._bimi.${dominio}" | grep -i "BIMI1" || true)

    # SPF
    if [[ -z "$spf_check" ]]; then
        recomendaciones+=("Crear registro SPF con política -all")
    elif ! echo "$spf_check" | grep -q "\-all"; then
        if ! echo "$spf_check" | grep -q "redirect="; then
            recomendaciones+=("Endurecer SPF: migrar a -all")
        fi
    fi

    # DMARC
    if [[ -z "$dmarc_check" ]]; then
        recomendaciones+=("Implementar DMARC (empezar con p=none + rua)")
    elif echo "$dmarc_check" | grep -qP 'p=none' 2>/dev/null; then
        recomendaciones+=("DMARC: evolucionar none → quarantine → reject")
    elif echo "$dmarc_check" | grep -qP 'p=quarantine' 2>/dev/null; then
        recomendaciones+=("DMARC: evolucionar quarantine → reject")
    fi

    # DNSSEC + DANE
    if [[ -z "$dnssec_present" ]]; then
        recomendaciones+=("Habilitar DNSSEC para proteger integridad DNS")
        recomendaciones+=("Tras DNSSEC, implementar DANE/TLSA en MX")
    fi

    # MTA-STS
    if [[ -z "$mta_sts_check" ]]; then
        recomendaciones+=("Implementar MTA-STS para forzar TLS en tránsito")
    fi

    # TLS-RPT
    if [[ -z "$tlsrpt_check" ]]; then
        recomendaciones+=("Añadir TLS-RPT para recibir reportes de fallos TLS")
    fi

    # BIMI
    if [[ -z "$bimi_check" ]]; then
        local dmarc_pol
        dmarc_pol=$(echo "$dmarc_check" | grep -oP 'p=\K[^;]+' | tr -d '"' | head -1 || true)
        if [[ "$dmarc_pol" == "reject" ]] || [[ "$dmarc_pol" == "quarantine" ]]; then
            recomendaciones+=("Considerar BIMI para mostrar logo de marca en bandejas")
        fi
    fi

    # MX
    if [[ "$TIENE_MX" == false ]]; then
        recomendaciones+=("Configurar registros MX para recibir correo")
    fi

    # Recuadro
    printf "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}\n"
    linea_vacia
    linea_recuadro "${BOLD}                    RESULTADO FINAL${NC}"
    linea_vacia
    printf "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}\n"
    linea_vacia
    linea_recuadro "   ${color}[${barra}]${NC}  ${SCORE}/${MAX_SCORE} puntos (${porcentaje}%)"
    linea_vacia
    local linea_nivel
    linea_nivel=$(printf "   Nivel de seguridad: %-12s %s" "$nivel" "$emoji")
    local visible_nivel
    visible_nivel=$(printf '%b' "   Nivel de seguridad: ${nivel}  ${emoji}" | sed 's/\x1b\[[0-9;]*m//g')
    local len_nivel=${#visible_nivel}
    len_nivel=$((len_nivel + 1))
    local pad_nivel=$((W - len_nivel))
    if [[ $pad_nivel -lt 0 ]]; then pad_nivel=0; fi
    printf "${CYAN}║${NC}   Nivel de seguridad: ${color}${BOLD}${nivel}${NC}  ${emoji}%*s${CYAN}║${NC}\n" "$pad_nivel" ""
    linea_vacia

    # Tabla de checks rápida
    printf "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}\n"
    linea_recuadro " ${BOLD}Resumen de checks:${NC}"
    linea_vacia

    local check_mx check_spf check_dkim check_dmarc check_dane check_sts check_tlsrpt check_bimi
    [[ "$TIENE_MX" == true ]] && check_mx="${OK}" || check_mx="${FAIL}"
    [[ -n "$spf_check" ]] && check_spf="${OK}" || check_spf="${FAIL}"
    # DKIM: re-check rápido
    local dkim_quick
    dkim_quick=$(safe_dig +short TXT "google._domainkey.${dominio}" 2>/dev/null | grep -i "p=" || \
                 safe_dig +short TXT "selector1._domainkey.${dominio}" 2>/dev/null | grep -i "p=" || \
                 safe_dig +short TXT "default._domainkey.${dominio}" 2>/dev/null | grep -i "p=" || true)
    [[ -n "$dkim_quick" ]] && check_dkim="${OK}" || check_dkim="${WARN}"
    [[ -n "$dmarc_check" ]] && check_dmarc="${OK}" || check_dmarc="${FAIL}"
    [[ -n "$dnssec_present" ]] && check_dane="${WARN}" || check_dane="${FAIL}"
    [[ -n "$mta_sts_check" ]] && check_sts="${OK}" || check_sts="${FAIL}"
    [[ -n "$tlsrpt_check" ]] && check_tlsrpt="${OK}" || check_tlsrpt="${FAIL}"
    [[ -n "$bimi_check" ]] && check_bimi="${OK}" || check_bimi="${INFO}"

    linea_recuadro "   ${check_mx} MX    ${check_spf} SPF    ${check_dkim} DKIM    ${check_dmarc} DMARC"
    linea_recuadro "   ${check_dane} DANE  ${check_sts} MTA-STS ${check_tlsrpt} TLS-RPT ${check_bimi} BIMI"
    linea_vacia

    printf "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}\n"
    linea_recuadro " ${BOLD}Recomendaciones:${NC}"
    linea_vacia

    if [[ ${#recomendaciones[@]} -eq 0 ]]; then
        linea_recuadro "  ${GREEN}✓ Configuración excelente. Revisar periódicamente.${NC}"
    else
        local i=1
        for rec in "${recomendaciones[@]}"; do
            linea_recuadro "  ${YELLOW}${i}. ${rec}${NC}"
            i=$((i + 1))
        done
    fi

    linea_vacia

    # Nota sobre herramientas opcionales
    if [[ "$TIENE_OPENSSL" != true ]] || [[ "$TIENE_CURL" != true ]]; then
        printf "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}\n"
        linea_recuadro " ${BOLD}Mejorar esta auditoría:${NC}"
        linea_vacia
        if [[ "$TIENE_OPENSSL" != true ]]; then
            linea_recuadro "  ${INFO} Instalar ${CYAN}openssl${NC} para verificar certificados TLS"
        fi
        if [[ "$TIENE_CURL" != true ]]; then
            linea_recuadro "  ${INFO} Instalar ${CYAN}curl${NC} para validar políticas MTA-STS y BIMI"
        fi
        linea_vacia
    fi

    printf "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}\n"
    printf "\n"
}

# ─── Main ────────────────────────────────────────────────────────────
main() {
    comprobar_dependencias

    local dominio="${1:-}"

    if [[ -z "$dominio" ]]; then
        printf "Introduce el dominio a auditar: "
        read -r dominio
    fi

    dominio=$(echo "$dominio" | sed -E 's|^https?://||; s|/.*||; s|^www\.||')

    validar_dominio "$dominio"
    verificar_dominio_existe "$dominio"
    mostrar_banner "$dominio"

    # 1. MX (primero para decidir si continuar)
    auditar_mx "$dominio"

    if [[ "$TIENE_MX" == false ]]; then
        mostrar_aviso_sin_correo "$dominio"
    fi

    # 2-4. Autenticación de correo
    auditar_spf "$dominio"
    auditar_dkim "$dominio"
    auditar_dmarc "$dominio"

    # 5. DANE/TLSA
    auditar_dane "$dominio"

    # 6-7. Seguridad TLS en tránsito
    auditar_mta_sts "$dominio"
    auditar_tls_rpt "$dominio"

    # 8. Marca
    auditar_bimi "$dominio"

    # 9. Certificados TLS (requiere openssl)
    auditar_tls_certs "$dominio"

    # 10. Protección de subdominios
    auditar_subdominios "$dominio"

    # Resultado final
    mostrar_resumen "$dominio"
}

main "$@"
