#!/bin/bash
#
# email-audit.sh — Auditoría de autenticación de correo electrónico
# Verifica SPF, DKIM, DMARC, MX y DANE/TLSA de un dominio
#
# Uso: ./email-audit.sh [dominio]
#       Si no se pasa argumento, lo solicita de forma interactiva.

# No usar set -e: muchos comandos (dig, grep, nc) devuelven exit != 0
# legítimamente cuando no hay resultados, y eso aborta el script.
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

# ─── Iconos de estado ────────────────────────────────────────────────
OK="${GREEN}✓${NC}"
WARN="${YELLOW}⚠${NC}"
FAIL="${RED}✗${NC}"
INFO="${CYAN}ℹ${NC}"

# ─── Puntuación global ───────────────────────────────────────────────
SCORE=0
MAX_SCORE=0
MX_SERVERS=()

# Ancho interno del recuadro (entre los bordes ║)
W=62

sumar_puntos() {
    SCORE=$((SCORE + $1))
    MAX_SCORE=$((MAX_SCORE + $2))
}

# ─── Utilidad: línea con padding dentro de recuadro ──────────────────
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

# ─── Utilidad: ejecutar dig de forma segura ──────────────────────────
# Evita que fallos de dig o grep propaguen errores
safe_dig() {
    dig "$@" 2>/dev/null || true
}

# ─── Comprobación de dependencias ────────────────────────────────────
comprobar_dependencias() {
    local faltan=()
    for cmd in dig; do
        if ! command -v "$cmd" &>/dev/null; then
            faltan+=("$cmd")
        fi
    done
    if [[ ${#faltan[@]} -gt 0 ]]; then
        printf "${RED}Error:${NC} Faltan comandos: %s\n" "${faltan[*]}"
        printf "Instálalos con:\n"
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

separador() {
    printf "${BLUE}┌──────────────────────────────────────────────────────────────┐${NC}\n"
}

separador_fin() {
    printf "${BLUE}└──────────────────────────────────────────────────────────────┘${NC}\n\n"
}

# ─── SPF ─────────────────────────────────────────────────────────────
auditar_spf() {
    local dominio="$1"
    separador
    printf "${BLUE}│${NC} ${BOLD}1. SPF (Sender Policy Framework)${NC}\n"
    printf "${BLUE}│${NC} ${DIM}Define qué servidores pueden enviar correo por este dominio${NC}\n"
    printf "${BLUE}│${NC}\n"

    local spf
    spf=$(safe_dig +short TXT "$dominio" | grep -i "v=spf1" || true)

    if [[ -z "$spf" ]]; then
        printf "${BLUE}│${NC}  ${FAIL} No se encontró registro SPF\n"
        printf "${BLUE}│${NC}    ${YELLOW}→ Vulnerable a spoofing${NC}\n"
        sumar_puntos 0 3
        separador_fin
        return
    fi

    printf "${BLUE}│${NC}  ${OK} Registro encontrado:\n"
    printf "${BLUE}│${NC}    ${CYAN}%s${NC}\n" "$spf"
    printf "${BLUE}│${NC}\n"

    # Comprobar redirect= (delega a otro dominio, hereda su all)
    local tiene_redirect=""
    tiene_redirect=$(echo "$spf" | grep -oP 'redirect=\K[^ "]+' || true)

    if [[ -n "$tiene_redirect" ]]; then
        printf "${BLUE}│${NC}  ${INFO} Usa ${CYAN}redirect=${tiene_redirect}${NC}\n"

        local spf_redir
        spf_redir=$(safe_dig +short TXT "$tiene_redirect" | grep -i "v=spf1" || true)
        if [[ -n "$spf_redir" ]]; then
            # Mostrar solo primeros 70 chars si es muy largo
            local spf_redir_corto="$spf_redir"
            local spf_redir_limpio
            spf_redir_limpio=$(printf '%s' "$spf_redir" | tr -d '"')
            if [[ ${#spf_redir_limpio} -gt 70 ]]; then
                spf_redir_corto="${spf_redir_limpio:0:67}..."
            fi
            printf "${BLUE}│${NC}    SPF delegado: ${DIM}%s${NC}\n" "$spf_redir_corto"

            if echo "$spf_redir" | grep -q "\-all"; then
                printf "${BLUE}│${NC}  ${OK} Política heredada: ${GREEN}ESTRICTA (-all)${NC}\n"
                sumar_puntos 3 3
            elif echo "$spf_redir" | grep -q "\~all"; then
                printf "${BLUE}│${NC}  ${WARN} Política heredada: ${YELLOW}SUAVE (~all)${NC}\n"
                sumar_puntos 2 3
            else
                printf "${BLUE}│${NC}  ${WARN} Política heredada no determinada claramente\n"
                sumar_puntos 1 3
            fi
        else
            printf "${BLUE}│${NC}  ${WARN} No se pudo resolver el SPF del dominio redirect\n"
            sumar_puntos 1 3
        fi
    elif echo "$spf" | grep -q "\-all"; then
        printf "${BLUE}│${NC}  ${OK} Política: ${GREEN}ESTRICTA (-all)${NC} — rechaza correo no autorizado\n"
        sumar_puntos 3 3
    elif echo "$spf" | grep -q "\~all"; then
        printf "${BLUE}│${NC}  ${WARN} Política: ${YELLOW}SUAVE (~all)${NC} — marca como sospechoso, no rechaza\n"
        sumar_puntos 2 3
    elif echo "$spf" | grep -q "\?all"; then
        printf "${BLUE}│${NC}  ${WARN} Política: ${YELLOW}NEUTRAL (?all)${NC} — sin acción\n"
        sumar_puntos 1 3
    elif echo "$spf" | grep -q "+all"; then
        printf "${BLUE}│${NC}  ${FAIL} Política: ${RED}ABIERTA (+all)${NC} — ¡cualquiera puede suplantar!\n"
        sumar_puntos 0 3
    else
        printf "${BLUE}│${NC}  ${WARN} No se detectó mecanismo 'all' explícito\n"
        sumar_puntos 1 3
    fi

    # Contar lookups DNS (límite de 10 según RFC 7208)
    local lookups
    lookups=$(echo "$spf" | grep -oE '(include:|a:|mx:|ptr:|redirect=)' | wc -l | tr -d ' ')
    if [[ "$lookups" -gt 10 ]]; then
        printf "${BLUE}│${NC}  ${FAIL} DNS lookups: ${RED}${lookups}/10${NC} — excede RFC 7208\n"
    elif [[ "$lookups" -gt 7 ]]; then
        printf "${BLUE}│${NC}  ${WARN} DNS lookups: ${YELLOW}${lookups}/10${NC} — cerca del límite\n"
    else
        printf "${BLUE}│${NC}  ${OK} DNS lookups: ${GREEN}${lookups}/10${NC}\n"
    fi
    separador_fin
}

# ─── DKIM ────────────────────────────────────────────────────────────
auditar_dkim() {
    local dominio="$1"
    separador
    printf "${BLUE}│${NC} ${BOLD}2. DKIM (DomainKeys Identified Mail)${NC}\n"
    printf "${BLUE}│${NC} ${DIM}Firma criptográfica que verifica la integridad del mensaje${NC}\n"
    printf "${BLUE}│${NC}\n"

    local selectores=("default" "google" "selector1" "selector2" "k1" "k2"
                      "mail" "dkim" "s1" "s2" "smtp" "mandrill" "everlytickey1"
                      "mxvault" "cm" "protonmail" "protonmail2" "protonmail3"
                      "20230601" "20221208" "20210112" "20161025"
                      "sig1" "m1" "smtp2" "email")

    local encontrados=0

    for selector in "${selectores[@]}"; do
        local resultado
        resultado=$(safe_dig +short TXT "${selector}._domainkey.${dominio}" || true)
        if [[ -n "$resultado" ]] && echo "$resultado" | grep -qi "p=" ; then
            if [[ $encontrados -eq 0 ]]; then
                printf "${BLUE}│${NC}  ${OK} Registros DKIM encontrados:\n"
            fi
            printf "${BLUE}│${NC}    Selector: ${CYAN}%-15s${NC} → ${GREEN}Presente${NC}\n" "$selector"
            encontrados=$((encontrados + 1))
        fi
    done

    if [[ $encontrados -eq 0 ]]; then
        printf "${BLUE}│${NC}  ${WARN} Sin registros DKIM en selectores comunes\n"
        printf "${BLUE}│${NC}    ${YELLOW}→ Puede usar un selector personalizado no probado${NC}\n"
        printf "${BLUE}│${NC}    ${DIM}Prueba manual: dig TXT <selector>._domainkey.${dominio}${NC}\n"
        sumar_puntos 0 2
    else
        printf "${BLUE}│${NC}  ${OK} Total: ${GREEN}${encontrados}${NC} selector(es) DKIM verificados\n"
        sumar_puntos 2 2
    fi
    separador_fin
}

# ─── DMARC ───────────────────────────────────────────────────────────
auditar_dmarc() {
    local dominio="$1"
    separador
    printf "${BLUE}│${NC} ${BOLD}3. DMARC (Domain-based Message Authentication, Reporting & Conformance)${NC}\n"
    printf "${BLUE}│${NC} ${DIM}Política que une SPF y DKIM e indica cómo tratar fallos${NC}\n"
    printf "${BLUE}│${NC}\n"

    local dmarc_raw
    dmarc_raw=$(safe_dig +noall +answer TXT "_dmarc.${dominio}" || true)

    # Extraer solo la línea que contiene v=DMARC1 (ignora CNAMEs)
    local dmarc
    dmarc=$(echo "$dmarc_raw" | grep -oP '"v=DMARC1[^"]*"' | head -1 || true)

    if [[ -z "$dmarc" ]]; then
        printf "${BLUE}│${NC}  ${FAIL} No se encontró registro DMARC\n"
        printf "${BLUE}│${NC}    ${YELLOW}→ Sin instrucciones para correo no autenticado${NC}\n"
        sumar_puntos 0 3
        separador_fin
        return
    fi

    # Detectar CNAME (delegación)
    local cname_target
    cname_target=$(echo "$dmarc_raw" | awk '/CNAME/{print $NF}' | head -1 || true)

    printf "${BLUE}│${NC}  ${OK} Registro encontrado:\n"
    if [[ -n "$cname_target" ]]; then
        printf "${BLUE}│${NC}    ${DIM}(delegado vía CNAME → ${cname_target})${NC}\n"
    fi
    printf "${BLUE}│${NC}    ${CYAN}%s${NC}\n" "$dmarc"
    printf "${BLUE}│${NC}\n"

    # Política principal
    local politica
    politica=$(echo "$dmarc" | grep -oP 'p=\K[^;]+' | tr -d '"' | head -1 || true)
    case "$politica" in
        reject)
            printf "${BLUE}│${NC}  ${OK} Política: ${GREEN}REJECT${NC} — rechaza correo no autenticado\n"
            sumar_puntos 3 3
            ;;
        quarantine)
            printf "${BLUE}│${NC}  ${WARN} Política: ${YELLOW}QUARANTINE${NC} — envía a spam\n"
            sumar_puntos 2 3
            ;;
        none)
            printf "${BLUE}│${NC}  ${WARN} Política: ${YELLOW}NONE${NC} — solo monitoriza, sin protección activa\n"
            sumar_puntos 1 3
            ;;
        *)
            printf "${BLUE}│${NC}  ${WARN} Política no reconocida: '${politica}'\n"
            sumar_puntos 0 3
            ;;
    esac

    # Subdominio
    local sub_politica
    sub_politica=$(echo "$dmarc" | grep -oP 'sp=\K[^;]+' | tr -d '"' | head -1 || true)
    if [[ -n "$sub_politica" ]]; then
        printf "${BLUE}│${NC}    Subdominios (sp): ${CYAN}${sub_politica}${NC}\n"
    fi

    # Porcentaje
    local pct
    pct=$(echo "$dmarc" | grep -oP 'pct=\K[0-9]+' | head -1 || true)
    if [[ -n "$pct" ]] && [[ "$pct" -lt 100 ]]; then
        printf "${BLUE}│${NC}  ${WARN} Aplicado solo al ${YELLOW}${pct}%%${NC} del correo (objetivo: 100%%)\n"
    fi

    # Reportes
    local rua ruf
    rua=$(echo "$dmarc" | grep -oP 'rua=\K[^;]+' | tr -d '"' | head -1 || true)
    ruf=$(echo "$dmarc" | grep -oP 'ruf=\K[^;]+' | tr -d '"' | head -1 || true)
    printf "${BLUE}│${NC}\n"
    printf "${BLUE}│${NC}  Reportes:\n"
    if [[ -n "$rua" ]]; then
        printf "${BLUE}│${NC}    ${OK} Agregados (rua): ${CYAN}%s${NC}\n" "$rua"
    else
        printf "${BLUE}│${NC}    ${WARN} Sin reportes agregados (rua)\n"
    fi
    if [[ -n "$ruf" ]]; then
        printf "${BLUE}│${NC}    ${OK} Forenses  (ruf): ${CYAN}%s${NC}\n" "$ruf"
    else
        printf "${BLUE}│${NC}    ${INFO} Sin reportes forenses (ruf) — opcional\n"
    fi
    separador_fin
}

# ─── MX ──────────────────────────────────────────────────────────────
auditar_mx() {
    local dominio="$1"
    separador
    printf "${BLUE}│${NC} ${BOLD}4. MX (Mail eXchange)${NC}\n"
    printf "${BLUE}│${NC} ${DIM}Servidores responsables de recibir correo para el dominio${NC}\n"
    printf "${BLUE}│${NC}\n"

    local mx
    mx=$(safe_dig +short MX "$dominio" | sort -n || true)

    if [[ -z "$mx" ]]; then
        printf "${BLUE}│${NC}  ${FAIL} No se encontraron registros MX\n"
        printf "${BLUE}│${NC}    ${YELLOW}→ Este dominio no puede recibir correo${NC}\n"
        sumar_puntos 0 2
        separador_fin
        return
    fi

    printf "${BLUE}│${NC}  ${OK} Servidores MX encontrados:\n"
    printf "${BLUE}│${NC}\n"
    printf "${BLUE}│${NC}    ${DIM}%-12s %-45s${NC}\n" "PRIORIDAD" "SERVIDOR"
    printf "${BLUE}│${NC}    ${DIM}%-12s %-45s${NC}\n" "─────────" "────────────────────────────────"

    MX_SERVERS=()

    while IFS= read -r linea; do
        [[ -z "$linea" ]] && continue
        local prioridad servidor
        prioridad=$(echo "$linea" | awk '{print $1}')
        servidor=$(echo "$linea" | awk '{print $2}')
        printf "${BLUE}│${NC}    ${CYAN}%-12s${NC} ${CYAN}%s${NC}\n" "$prioridad" "$servidor"
        MX_SERVERS+=("$servidor")
    done <<< "$mx"

    sumar_puntos 2 2

    # Detectar proveedor
    printf "${BLUE}│${NC}\n"
    printf "${BLUE}│${NC}  Proveedor detectado: "
    if echo "$mx" | grep -qi "google\|gmail\|googlemail"; then
        printf "${GREEN}Google Workspace${NC}\n"
    elif echo "$mx" | grep -qi "outlook\|microsoft"; then
        printf "${GREEN}Microsoft 365${NC}\n"
    elif echo "$mx" | grep -qi "protonmail\|proton"; then
        printf "${GREEN}ProtonMail${NC}\n"
    elif echo "$mx" | grep -qi "zoho"; then
        printf "${GREEN}Zoho Mail${NC}\n"
    elif echo "$mx" | grep -qi "mimecast"; then
        printf "${GREEN}Mimecast${NC}\n"
    elif echo "$mx" | grep -qi "barracuda"; then
        printf "${GREEN}Barracuda${NC}\n"
    elif echo "$mx" | grep -qi "pphosted\|proofpoint"; then
        printf "${GREEN}Proofpoint${NC}\n"
    elif echo "$mx" | grep -qi "ovh"; then
        printf "${GREEN}OVH${NC}\n"
    elif echo "$mx" | grep -qi "ionos\|1and1\|perfora\|kundenserver"; then
        printf "${GREEN}IONOS (1&1)${NC}\n"
    else
        printf "${YELLOW}No identificado (hosting propio o proveedor menor)${NC}\n"
    fi
    separador_fin
}

# ─── DANE / TLSA ─────────────────────────────────────────────────────
auditar_dane() {
    local dominio="$1"
    separador
    printf "${BLUE}│${NC} ${BOLD}5. DANE/TLSA (DNS-based Authentication of Named Entities)${NC}\n"
    printf "${BLUE}│${NC} ${DIM}Vincula certificados TLS a registros DNS (requiere DNSSEC)${NC}\n"
    printf "${BLUE}│${NC}\n"

    # Verificar DNSSEC
    local dnssec_ok=false
    local dnssec_check
    dnssec_check=$(safe_dig +dnssec +short DNSKEY "$dominio" || true)

    if [[ -n "$dnssec_check" ]]; then
        local ad_check
        ad_check=$(safe_dig +dnssec "$dominio" A | grep -c "flags:.*ad" || true)
        if [[ "$ad_check" -gt 0 ]]; then
            printf "${BLUE}│${NC}  ${OK} DNSSEC: ${GREEN}Validado (flag AD presente)${NC}\n"
            dnssec_ok=true
        else
            printf "${BLUE}│${NC}  ${WARN} DNSSEC: ${YELLOW}DNSKEY encontrado, sin validación AD${NC}\n"
            printf "${BLUE}│${NC}    ${DIM}Puede depender del resolver utilizado${NC}\n"
            dnssec_ok=true
        fi
    else
        printf "${BLUE}│${NC}  ${FAIL} DNSSEC: ${RED}No habilitado${NC}\n"
        printf "${BLUE}│${NC}    ${YELLOW}→ DANE requiere DNSSEC para funcionar${NC}\n"
    fi

    printf "${BLUE}│${NC}\n"

    if [[ ${#MX_SERVERS[@]} -eq 0 ]]; then
        printf "${BLUE}│${NC}  ${WARN} Sin servidores MX — no se puede verificar TLSA\n"
        sumar_puntos 0 2
        separador_fin
        return
    fi

    local tlsa_encontrados=0
    local tlsa_total=0
    local starttls_count=0

    printf "${BLUE}│${NC}  Registros TLSA (puerto 25/SMTP) por servidor MX:\n"
    printf "${BLUE}│${NC}\n"

    for mx_server in "${MX_SERVERS[@]}"; do
        mx_server="${mx_server%.}"
        tlsa_total=$((tlsa_total + 1))

        local tlsa
        tlsa=$(safe_dig +short TLSA "_25._tcp.${mx_server}" || true)

        if [[ -n "$tlsa" ]]; then
            tlsa_encontrados=$((tlsa_encontrados + 1))
            printf "${BLUE}│${NC}    ${OK} ${CYAN}%s${NC}\n" "$mx_server"

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

                printf "${BLUE}│${NC}       Uso: ${GREEN}%s${NC} (%s)\n" "$usage" "$uso_desc"
                printf "${BLUE}│${NC}       Selector: %s (%s) · Match: %s (%s)\n" \
                    "$selector" "$sel_desc" "$matching" "$match_desc"
            done <<< "$tlsa"
        else
            printf "${BLUE}│${NC}    ${FAIL} ${CYAN}%s${NC} → Sin TLSA\n" "$mx_server"
        fi

        # STARTTLS — solo si nc y timeout están disponibles
        if command -v timeout &>/dev/null && command -v nc &>/dev/null; then
            local smtp_banner
            smtp_banner=$(timeout 5 bash -c "echo 'EHLO test' | nc -w3 \"${mx_server}\" 25" 2>/dev/null || true)
            if [[ -n "$smtp_banner" ]] && echo "$smtp_banner" | grep -qi "STARTTLS"; then
                printf "${BLUE}│${NC}       ${OK} STARTTLS: ${GREEN}Soportado${NC}\n"
                starttls_count=$((starttls_count + 1))
            elif [[ -n "$smtp_banner" ]]; then
                printf "${BLUE}│${NC}       ${WARN} STARTTLS: ${YELLOW}No anunciado en EHLO${NC}\n"
            else
                printf "${BLUE}│${NC}       ${INFO} STARTTLS: ${DIM}Sin respuesta en puerto 25${NC}\n"
            fi
        fi
        printf "${BLUE}│${NC}\n"
    done

    # Puntuación DANE
    printf "${BLUE}│${NC}  Resumen DANE/TLSA:\n"
    if [[ $tlsa_encontrados -gt 0 ]] && [[ "$dnssec_ok" == true ]]; then
        printf "${BLUE}│${NC}    ${OK} ${GREEN}${tlsa_encontrados}/${tlsa_total}${NC} servidores MX con TLSA\n"
        if [[ $tlsa_encontrados -eq $tlsa_total ]]; then
            sumar_puntos 2 2
        else
            sumar_puntos 1 2
        fi
    elif [[ $tlsa_encontrados -gt 0 ]]; then
        printf "${BLUE}│${NC}    ${WARN} TLSA encontrados pero ${YELLOW}DNSSEC no validado${NC}\n"
        sumar_puntos 1 2
    else
        printf "${BLUE}│${NC}    ${FAIL} Sin registros TLSA en ningún servidor MX\n"
        if [[ "$dnssec_ok" == true ]]; then
            printf "${BLUE}│${NC}    ${YELLOW}→ DNSSEC activo: buen momento para implementar DANE${NC}\n"
        else
            printf "${BLUE}│${NC}    ${YELLOW}→ Habilitar DNSSEC primero, luego añadir TLSA${NC}\n"
        fi
        sumar_puntos 0 2
    fi

    if [[ $starttls_count -gt 0 ]]; then
        printf "${BLUE}│${NC}    ${OK} STARTTLS verificado en ${GREEN}${starttls_count}${NC} servidor(es)\n"
    fi
    separador_fin
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

    # Barra de progreso
    local barra=""
    local llenos=$((porcentaje / 5))
    local vacios=$((20 - llenos))
    for ((i=0; i<llenos; i++)); do barra+="█"; done
    for ((i=0; i<vacios; i++)); do barra+="░"; done

    # Recopilar recomendaciones
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

    # Imprimir recuadro final
    printf "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}\n"
    linea_vacia
    linea_recuadro "${BOLD}                    RESULTADO FINAL${NC}"
    linea_vacia
    printf "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}\n"
    linea_vacia
    linea_recuadro "   ${color}[${barra}]${NC}  ${SCORE}/${MAX_SCORE} puntos (${porcentaje}%)"
    linea_vacia
    linea_recuadro "   Nivel de seguridad: ${color}${BOLD}${nivel}${NC}  ${emoji}"
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
    mostrar_banner "$dominio"

    auditar_spf "$dominio"
    auditar_dkim "$dominio"
    auditar_dmarc "$dominio"
    auditar_mx "$dominio"
    auditar_dane "$dominio"
    mostrar_resumen "$dominio"
}

main "$@"
