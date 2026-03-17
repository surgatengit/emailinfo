#!/bin/bash
#
# email-audit.sh — Auditoría de autenticación de correo electrónico
# Verifica SPF, DKIM, DMARC, MX y DANE/TLSA de un dominio
#
# Uso: ./email-audit.sh [dominio]
#       Si no se pasa argumento, lo solicita de forma interactiva.

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

# Línea de sección con borde izquierdo │
L() {
    local texto="${1:-}"
    printf "${BLUE}│${NC} %b\n" "$texto"
}

# Línea de sección vacía con borde
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
    # Si ANY no devuelve nada, probar con A y NS
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

    printf "\n"
    printf "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}\n"
    linea_vacia
    linea_recuadro "${BOLD}      AUDITORÍA DE AUTENTICACIÓN DE CORREO ELECTRÓNICO${NC}"
    linea_vacia
    printf "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}\n"
    linea_recuadro "  Dominio:  ${dominio}"
    linea_recuadro "  Fecha:    ${fecha}"
    linea_recuadro "  Checks:   SPF · DKIM · DMARC · MX · DANE/TLSA"
    printf "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}\n"
    printf "\n"
}

# ─── SPF ─────────────────────────────────────────────────────────────
auditar_spf() {
    local dominio="$1"
    seccion_inicio
    L "${BOLD}2. SPF (Sender Policy Framework)${NC}"
    L "${DIM}Define qué servidores pueden enviar correo por este dominio${NC}"
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

# ─── DKIM ────────────────────────────────────────────────────────────
auditar_dkim() {
    local dominio="$1"
    seccion_inicio
    L "${BOLD}3. DKIM (DomainKeys Identified Mail)${NC}"
    L "${DIM}Firma criptográfica que verifica la integridad del mensaje${NC}"
    LV
# https://zk.email/blog/archive Articulo interesante, usados los selectores mas comunes.
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

# ─── DMARC ───────────────────────────────────────────────────────────
auditar_dmarc() {
    local dominio="$1"
    seccion_inicio
    L "${BOLD}4. DMARC (Domain-based Message Authentication, Reporting & Conformance)${NC}"
    L "${DIM}Política que une SPF y DKIM e indica cómo tratar fallos${NC}"
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

# ─── MX ──────────────────────────────────────────────────────────────
auditar_mx() {
    local dominio="$1"
    seccion_inicio
    L "${BOLD}1. MX (Mail eXchange)${NC}"
    L "${DIM}Servidores responsables de recibir correo para el dominio${NC}"
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

    # --- No identificado: mostrar hostname como pista ---
    else
        local mx_host
        mx_host=$(echo "$mx" | head -1 | awk '{print $2}')
        printf "${YELLOW}No identificado${NC} (${DIM}${mx_host}${NC})\n"
    fi
    seccion_fin
}

# ─── DANE / TLSA ─────────────────────────────────────────────────────
auditar_dane() {
    local dominio="$1"
    seccion_inicio
    L "${BOLD}5. DANE/TLSA (DNS-based Authentication of Named Entities)${NC}"
    L "${DIM}Vincula certificados TLS a registros DNS (requiere DNSSEC)${NC}"
    LV

    # DNSSEC
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

        # STARTTLS
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

    local spf_check dmarc_check dnssec_present
    spf_check=$(safe_dig +short TXT "$dominio" | grep -i "v=spf1" || true)
    dmarc_check=$(safe_dig +noall +answer TXT "_dmarc.${dominio}" | grep -oP '"v=DMARC1[^"]*"' | head -1 || true)
    dnssec_present=$(safe_dig +short DNSKEY "$dominio" || true)

    if [[ -z "$spf_check" ]]; then
        recomendaciones+=("Crear registro SPF con política -all")
    elif ! echo "$spf_check" | grep -q "\-all"; then
        if ! echo "$spf_check" | grep -q "redirect="; then
            recomendaciones+=("Endurecer SPF: migrar a -all")
        fi
    fi

    if [[ -z "$dmarc_check" ]]; then
        recomendaciones+=("Implementar DMARC (empezar con p=none + rua)")
    elif echo "$dmarc_check" | grep -qP 'p=none' 2>/dev/null; then
        recomendaciones+=("DMARC: evolucionar none → quarantine → reject")
    elif echo "$dmarc_check" | grep -qP 'p=quarantine' 2>/dev/null; then
        recomendaciones+=("DMARC: evolucionar quarantine → reject")
    fi

    if [[ -z "$dnssec_present" ]]; then
        recomendaciones+=("Habilitar DNSSEC para proteger integridad DNS")
        recomendaciones+=("Tras DNSSEC, implementar DANE/TLSA en MX")
    fi

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
    # El emoji ocupa 2 columnas en terminal pero se mide como 1 carácter.
    # Compensamos restando 1 espacio con el truco de meterlo en el cálculo.
    local linea_nivel
    linea_nivel=$(printf "   Nivel de seguridad: %-12s %s" "$nivel" "$emoji")
    local visible_nivel
    visible_nivel=$(printf '%b' "   Nivel de seguridad: ${nivel}  ${emoji}" | sed 's/\x1b\[[0-9;]*m//g')
    local len_nivel=${#visible_nivel}
    # Sumar 1 por el ancho extra del emoji en terminal
    len_nivel=$((len_nivel + 1))
    local pad_nivel=$((W - len_nivel))
    if [[ $pad_nivel -lt 0 ]]; then pad_nivel=0; fi
    printf "${CYAN}║${NC}   Nivel de seguridad: ${color}${BOLD}${nivel}${NC}  ${emoji}%*s${CYAN}║${NC}\n" "$pad_nivel" ""
    linea_vacia
    printf "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}\n"
    linea_recuadro " ${BOLD}Recomendaciones:${NC}"
    linea_vacia

    if [[ ${#recomendaciones[@]} -eq 0 ]]; then
        linea_recuadro "  ${GREEN}✓ Configuración excelente. Revisar periódicamente.${NC}"
    else
        for rec in "${recomendaciones[@]}"; do
            linea_recuadro "  ${YELLOW}→ ${rec}${NC}"
        done
    fi

    linea_vacia
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

    # Primero comprobar MX para decidir si continuar
    auditar_mx "$dominio"

    # Si no hay MX, avisar y preguntar
    if [[ "$TIENE_MX" == false ]]; then
        mostrar_aviso_sin_correo "$dominio"
    fi

    auditar_spf "$dominio"
    auditar_dkim "$dominio"
    auditar_dmarc "$dominio"
    # MX ya se mostró arriba, no repetir
    auditar_dane "$dominio"
    mostrar_resumen "$dominio"
}

main "$@"
