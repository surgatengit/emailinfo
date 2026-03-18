#!/bin/bash
#
# email-audit.sh — Full email authentication audit
# Checks MX, SPF, DKIM, DMARC, DANE/TLSA, MTA-STS, TLS-RPT, BIMI,
# TLS certificates and subdomain protection.
#
# Usage: ./email-audit.sh [--lang es|en] [domain]
#        If no domain is given, it will be requested interactively.
#        Language is auto-detected from system locale (Spanish → ES, else EN).
#        Use --lang to force a language.
#
# Required dependencies: dig
# Optional dependencies:  openssl (TLS/certs), curl (MTA-STS policy)
#                          nc + timeout (basic STARTTLS)

set -uo pipefail

# ─── Colors ───────────────────────────────────────────────────────────
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

W=62  # inner box width

sumar_puntos() {
    SCORE=$((SCORE + $1))
    MAX_SCORE=$((MAX_SCORE + $2))
}

# ─── Language detection & i18n ────────────────────────────────────────
LANG_CODE=""

detect_language() {
    local sys_lang="${LANG:-${LC_ALL:-${LC_MESSAGES:-en}}}"
    if echo "$sys_lang" | grep -qi "^es"; then
        LANG_CODE="es"
    else
        LANG_CODE="en"
    fi
}

# Call detection first; may be overridden by --lang
detect_language

# Associative array for translations
declare -A T

load_strings_es() {
    # ── General ──
    T[error]="Error"
    T[missing_dig]="Falta el comando 'dig'."
    T[install_with]="Instálalo con:"
    T[enter_domain]="Introduce el dominio a auditar: "
    T[invalid_domain]="'%s' no parece un dominio válido."
    T[no_dns_records]="El dominio '%s' no tiene registros DNS."
    T[check_typo]="¿Está bien escrito? Comprueba que no haya erratas."
    T[audit_cancelled]="Auditoría cancelada."
    T[continue_anyway]="¿Continuar igualmente con la auditoría? [s/N]: "

    # ── Banner ──
    T[banner_title]="      AUDITORÍA DE AUTENTICACIÓN DE CORREO ELECTRÓNICO"
    T[banner_domain]="Dominio"
    T[banner_date]="Fecha"
    T[banner_checks]="Checks"
    T[banner_extras]="Extras"
    T[banner_extras_none]="ninguna"
    T[banner_checks_list]="MX · SPF · DKIM · DMARC · DANE/TLSA"
    T[banner_checks_list2]="MTA-STS · TLS-RPT · BIMI · TLS · Subdominios"

    # ── 1. MX ──
    T[mx_title]="1. MX (Mail eXchange)"
    T[mx_desc1]="Servidores responsables de recibir correo para el dominio."
    T[mx_desc2]="Sin registros MX el dominio no puede recibir email. La prioridad"
    T[mx_desc3]="(número menor = preferido) determina el orden de entrega."
    T[mx_not_found]="No se encontraron registros MX"
    T[mx_no_receive]="Este dominio no puede recibir correo"
    T[mx_found]="Servidores MX encontrados:"
    T[mx_priority]="PRIORIDAD"
    T[mx_server]="SERVIDOR"
    T[mx_provider]="Proveedor detectado"
    T[mx_provider_unknown]="No identificado"

    # ── 2. SPF ──
    T[spf_title]="2. SPF (Sender Policy Framework)"
    T[spf_desc1]="Define qué servidores IP tienen permiso para enviar correo en"
    T[spf_desc2]="nombre de este dominio. Sin SPF, cualquier servidor podría"
    T[spf_desc3]="enviar correo suplantando la identidad (spoofing). RFC 7208."
    T[spf_not_found]="No se encontró registro SPF"
    T[spf_vulnerable]="Vulnerable a spoofing"
    T[spf_found]="Registro encontrado:"
    T[spf_uses_redirect]="Usa"
    T[spf_delegated]="SPF delegado"
    T[spf_inherited_strict]="Política heredada: ESTRICTA (-all)"
    T[spf_inherited_soft]="Política heredada: SUAVE (~all)"
    T[spf_inherited_unknown]="Política heredada no determinada claramente"
    T[spf_redirect_fail]="No se pudo resolver el SPF del dominio redirect"
    T[spf_strict]="ESTRICTA (-all) — rechaza correo no autorizado"
    T[spf_soft]="SUAVE (~all) — marca como sospechoso, no rechaza"
    T[spf_neutral]="NEUTRAL (?all) — sin acción"
    T[spf_open]="ABIERTA (+all) — ¡cualquiera puede suplantar!"
    T[spf_no_all]="No se detectó mecanismo 'all' explícito"
    T[spf_policy]="Política"
    T[spf_lookups_exceed]="DNS lookups: %s/10 — excede RFC 7208"
    T[spf_lookups_near]="DNS lookups: %s/10 — cerca del límite"
    T[spf_lookups_ok]="DNS lookups: %s/10"

    # ── 3. DKIM ──
    T[dkim_title]="3. DKIM (DomainKeys Identified Mail)"
    T[dkim_desc1]="Firma criptográfica en cabeceras del mensaje que permite al"
    T[dkim_desc2]="receptor verificar que el correo no fue alterado en tránsito"
    T[dkim_desc3]="y que realmente proviene del dominio firmante. RFC 6376."
    T[dkim_found]="Registros DKIM encontrados:"
    T[dkim_selector]="Selector"
    T[dkim_present]="Presente"
    T[dkim_none]="Sin registros DKIM en selectores comunes"
    T[dkim_custom]="Puede usar un selector personalizado no probado"
    T[dkim_manual]="Prueba manual: dig TXT <selector>._domainkey.%s"
    T[dkim_total]="Total: %s selector(es) DKIM verificados"

    # ── 4. DMARC ──
    T[dmarc_title]="4. DMARC (Domain-based Message Authentication, Reporting & Conformance)"
    T[dmarc_desc1]="Política que une SPF y DKIM: indica a los receptores qué hacer"
    T[dmarc_desc2]="cuando un mensaje falla la autenticación (rechazar, cuarentena"
    T[dmarc_desc3]="o solo monitorizar). También permite recibir reportes. RFC 7489."
    T[dmarc_not_found]="No se encontró registro DMARC"
    T[dmarc_no_instructions]="Sin instrucciones para correo no autenticado"
    T[dmarc_found]="Registro encontrado:"
    T[dmarc_delegated]="delegado vía CNAME →"
    T[dmarc_policy]="Política"
    T[dmarc_reject]="REJECT — rechaza correo no autenticado"
    T[dmarc_quarantine]="QUARANTINE — envía a spam"
    T[dmarc_none]="NONE — solo monitoriza, sin protección activa"
    T[dmarc_unknown_policy]="Política no reconocida"
    T[dmarc_subdomains]="Subdominios (sp)"
    T[dmarc_pct]="Aplicado solo al %s%% del correo (objetivo: 100%%)"
    T[dmarc_reports]="Reportes:"
    T[dmarc_rua_ok]="Agregados (rua)"
    T[dmarc_rua_missing]="Sin reportes agregados (rua)"
    T[dmarc_ruf_ok]="Forenses  (ruf)"
    T[dmarc_ruf_missing]="Sin reportes forenses (ruf) — opcional"

    # ── 5. DANE/TLSA ──
    T[dane_title]="5. DANE/TLSA (DNS-based Authentication of Named Entities)"
    T[dane_desc1]="Vincula certificados TLS directamente a registros DNS, evitando"
    T[dane_desc2]="depender únicamente de CAs. Requiere DNSSEC para garantizar"
    T[dane_desc3]="la integridad de los registros TLSA. RFC 6698 / RFC 7672."
    T[dane_dnssec_validated]="DNSSEC: Validado (flag AD presente)"
    T[dane_dnssec_dnskey]="DNSSEC: DNSKEY encontrado, sin validación AD"
    T[dane_dnssec_resolver]="Puede depender del resolver utilizado"
    T[dane_dnssec_disabled]="DNSSEC: No habilitado"
    T[dane_dnssec_required]="DANE requiere DNSSEC para funcionar"
    T[dane_no_mx]="Sin servidores MX — no se puede verificar TLSA"
    T[dane_tlsa_header]="Registros TLSA (puerto 25/SMTP) por servidor MX:"
    T[dane_no_tlsa]="Sin TLSA"
    T[dane_starttls_supported]="STARTTLS: Soportado"
    T[dane_starttls_no]="STARTTLS: No anunciado en EHLO"
    T[dane_starttls_noresponse]="STARTTLS: Sin respuesta en puerto 25"
    T[dane_summary]="Resumen DANE/TLSA:"
    T[dane_mx_with_tlsa]="servidores MX con TLSA"
    T[dane_tlsa_no_dnssec]="TLSA encontrados pero DNSSEC no validado"
    T[dane_no_tlsa_any]="Sin registros TLSA en ningún servidor MX"
    T[dane_dnssec_active]="DNSSEC activo: buen momento para implementar DANE"
    T[dane_enable_dnssec]="Habilitar DNSSEC primero, luego añadir TLSA"
    T[dane_starttls_verified]="STARTTLS verificado en %s servidor(es)"
    T[dane_use_ca]="CA constraint (PKIX-TA)"
    T[dane_use_service]="Service cert (PKIX-EE)"
    T[dane_use_trust]="Trust anchor (DANE-TA)"
    T[dane_use_domain]="Domain cert (DANE-EE)"
    T[dane_use_unknown]="Desconocido"
    T[dane_sel_full]="Cert completo"
    T[dane_sel_pubkey]="Clave pública"
    T[dane_sel_unknown]="Desconocido"
    T[dane_match_unknown]="Desconocido"

    # ── 6. MTA-STS ──
    T[mtasts_title]="6. MTA-STS (SMTP MTA Strict Transport Security)"
    T[mtasts_desc1]="Permite al dominio declarar que sus servidores MX soportan TLS"
    T[mtasts_desc2]="y que los remitentes deben rechazar la entrega si no se puede"
    T[mtasts_desc3]="establecer una conexión TLS segura. Complementa DANE sin"
    T[mtasts_desc4]="requerir DNSSEC. RFC 8461."
    T[mtasts_not_found]="No se encontró registro DNS para MTA-STS"
    T[mtasts_no_protection]="Sin protección contra downgrade de TLS en SMTP"
    T[mtasts_bad_record]="Registro TXT encontrado pero no contiene v=STSv1"
    T[mtasts_found]="Registro DNS encontrado:"
    T[mtasts_policy_id]="ID de política"
    T[mtasts_downloading]="Descargando política desde HTTPS..."
    T[mtasts_download_fail]="No se pudo descargar"
    T[mtasts_dns_ok_no_policy]="El registro DNS existe pero la política no es accesible"
    T[mtasts_check_resolve]="Verificar que mta-sts.%s resuelve y tiene HTTPS"
    T[mtasts_downloaded]="Política descargada correctamente:"
    T[mtasts_mode_enforce]="Modo: ENFORCE — rechaza entrega sin TLS válido"
    T[mtasts_mode_testing]="Modo: TESTING — reporta fallos pero entrega igualmente"
    T[mtasts_mode_none]="Modo: NONE — desactiva la política"
    T[mtasts_mode_unknown]="Modo: %s — no reconocido"
    T[mtasts_maxage]="Vigencia (max_age)"
    T[mtasts_maxage_low]="max_age muy bajo (<1 día). Recomendado: ≥604800 (1 semana)"
    T[mtasts_mx_authorized]="Servidores MX autorizados:"
    T[mtasts_install_curl]="Instalar 'curl' para verificar la política HTTPS completa"
    T[mtasts_dns_only]="Solo se verificó el registro DNS (paso 1 de 2)"
    T[mtasts_days]="días"

    # ── 7. TLS-RPT ──
    T[tlsrpt_title]="7. TLS-RPT (SMTP TLS Reporting)"
    T[tlsrpt_desc1]="Permite recibir reportes cuando otros servidores tienen problemas"
    T[tlsrpt_desc2]="al establecer conexiones TLS con tus MX. Esencial para detectar"
    T[tlsrpt_desc3]="fallos de MTA-STS o DANE. Sin TLS-RPT los fallos son invisibles."
    T[tlsrpt_desc4]="RFC 8460."
    T[tlsrpt_not_found]="No se encontró registro TLS-RPT"
    T[tlsrpt_no_reports]="No recibirás reportes de fallos TLS de otros servidores"
    T[tlsrpt_bad_record]="Registro TXT encontrado pero no contiene v=TLSRPTv1"
    T[tlsrpt_found]="Registro encontrado:"
    T[tlsrpt_destinations]="Destinos de reporte:"

    # ── 8. BIMI ──
    T[bimi_title]="8. BIMI (Brand Indicators for Message Identification)"
    T[bimi_desc1]="Permite mostrar el logotipo de la marca junto al remitente en"
    T[bimi_desc2]="bandejas de entrada compatibles (Gmail, Yahoo, Apple Mail...)."
    T[bimi_desc3]="Requiere DMARC con p=quarantine o p=reject. Opcionalmente se"
    T[bimi_desc4]="puede incluir un VMC (Verified Mark Certificate) para mayor"
    T[bimi_desc5]="confianza. RFC pendiente (draft adoptado por múltiples ISPs)."
    T[bimi_not_found]="No se encontró registro BIMI"
    T[bimi_optional]="Opcional pero recomendado si DMARC está en enforce/quarantine"
    T[bimi_bad_record]="Registro TXT encontrado pero no contiene v=BIMI1"
    T[bimi_found]="Registro BIMI encontrado:"
    T[bimi_logo_accessible]="Logo accesible (HTTP %s)"
    T[bimi_logo_not_accessible]="Logo no accesible (HTTP %s)"
    T[bimi_no_logo]="No se encontró URL del logo (parámetro l=)"
    T[bimi_vmc_present]="Certificado de marca verificada presente"
    T[bimi_no_vmc]="Sin VMC (a=) — el logo puede no mostrarse en todos los clientes"

    # ── 9. TLS Certs ──
    T[tls_title]="9. Certificados TLS de servidores MX"
    T[tls_desc1]="Verifica el certificado TLS que presenta cada servidor MX al"
    T[tls_desc2]="negociar STARTTLS en puerto 25. Un certificado caducado, auto-"
    T[tls_desc3]="firmado o que no coincide con el hostname permite ataques MitM."
    T[tls_no_openssl]="openssl no disponible — se omite la verificación de certificados"
    T[tls_install_openssl]="Instalar con: apt install openssl / brew install openssl"
    T[tls_no_mx]="Sin servidores MX — nada que verificar"
    T[tls_checking_ports]="Comprobando accesibilidad de puertos SMTP..."
    T[tls_port_open]="Puerto %s accesible en %s"
    T[tls_port_blocked]="Puerto %s bloqueado o sin respuesta"
    T[tls_no_smtp]="Ningún puerto SMTP accesible (25, 587, 465)"
    T[tls_isp_blocking]="Tu ISP o firewall está bloqueando tráfico SMTP saliente."
    T[tls_common_home]="Esto es habitual en redes domésticas y proveedores cloud."
    T[tls_check_online]="Comprueba los certificados TLS online:"
    T[tls_ssl_tools]="Certificado, STARTTLS, PFS, DANE, Heartbleed"
    T[tls_checktls]="Conversación SMTP completa, MTA-STS, DANE"
    T[tls_hardenize]="Análisis completo de seguridad del dominio"
    T[tls_mxtoolbox]="SMTP TLS, certificados, diagnóstico MX"
    T[tls_internetnl]="Test estándar del gobierno holandés"
    T[tls_local_tip]="Para ejecutar este check localmente:"
    T[tls_vps_tip]="Usa un VPS con puerto 25 abierto (Hetzner, OVH...)"
    T[tls_vpn_tip]="Usa una VPN que no filtre SMTP"
    T[tls_network_tip]="Ejecuta desde una red sin restricciones de salida"
    T[tls_no_cert]="No se pudo obtener certificado TLS"
    T[tls_ports_tried]="Puertos probados: 25, 587, 465 — todos inaccesibles"
    T[tls_firewall]="Red/firewall bloqueando SMTP saliente, o servidor sin TLS"
    T[tls_manual]="Prueba manual: openssl s_client -starttls smtp -connect %s:25"
    T[tls_port]="Puerto"
    T[tls_subject]="Subject"
    T[tls_issuer]="Emisor"
    T[tls_obsolete]="obsoleto e inseguro"
    T[tls_expired]="Certificado CADUCADO hace %s días"
    T[tls_expires_urgent]="Caduca en %s días — renovar urgentemente"
    T[tls_expires_soon]="Caduca en %s días"
    T[tls_valid]="Válido %s días más (hasta %s)"
    T[tls_hostname_ok]="Hostname coincide con certificado"
    T[tls_hostname_cn_ok]="Hostname coincide con CN del certificado"
    T[tls_hostname_mismatch]="Hostname no coincide con SANs/CN del certificado"
    T[tls_self_signed]="Certificado AUTOFIRMADO"
    T[tls_summary]="Resumen TLS:"
    T[tls_certs_valid]="certificados válidos y vigentes"

    # ── 10. Subdomain protection ──
    T[sub_title]="10. Protección de subdominios contra spoofing"
    T[sub_desc1]="Los atacantes pueden suplantar correo desde subdominios como"
    T[sub_desc2]="mail.dominio.com o smtp.dominio.com si estos no tienen su propio"
    T[sub_desc3]="SPF restrictivo. Un 'null SPF' (v=spf1 -all) en subdominios que"
    T[sub_desc4]="no envían correo bloquea este vector de ataque."
    T[sub_subdomain]="SUBDOMINIO"
    T[sub_status]="ESTADO"
    T[sub_vulnerable]="Vulnerable"
    T[sub_protected]="Protegido"
    T[sub_restrictive]="Restrictivo"
    T[sub_softfail]="Softfail"
    T[sub_review]="Revisar"
    T[sub_none_found]="No se encontraron subdominios comunes con registros DNS"
    T[sub_none_normal]="Esto es normal si el dominio no usa subdominios de correo"
    T[sub_all_protected]="%s/%s subdominios protegidos"
    T[sub_unprotected]="%s subdominio(s) sin protección SPF"
    T[sub_add_record]="Añadir registro: v=spf1 -all"
    T[sub_dmarc_sp]="DMARC del dominio raíz incluye sp=%s para subdominios"
    T[sub_inherit_reject]="Los subdominios heredan política reject"
    T[sub_inherit_quarantine]="Los subdominios heredan política quarantine"
    T[sub_inherit_other]="Los subdominios heredan política %s"

    # ── No-mail warning ──
    T[nomail_title]="Este dominio no parece tener correo electrónico configurado"
    T[nomail_no_mx]="No se encontraron registros MX para"
    T[nomail_causes]="Posibles causas:"
    T[nomail_cause1]="Error al escribir el dominio"
    T[nomail_cause2]="El dominio no usa correo electrónico"
    T[nomail_cause3]="Los registros MX aún no se han propagado"

    # ── Summary ──
    T[summary_title]="RESULTADO FINAL"
    T[summary_level]="Nivel de seguridad"
    T[summary_good]="BUENO"
    T[summary_improvable]="MEJORABLE"
    T[summary_poor]="DEFICIENTE"
    T[summary_checks]="Resumen de checks:"
    T[summary_recommendations]="Recomendaciones:"
    T[summary_excellent]="Configuración excelente. Revisar periódicamente."
    T[summary_improve]="Mejorar esta auditoría:"
    T[summary_install_openssl]="Instalar openssl para verificar certificados TLS"
    T[summary_install_curl]="Instalar curl para validar políticas MTA-STS y BIMI"
    T[summary_points]="puntos"

    # ── Recommendation strings ──
    T[rec_create_spf]="Crear registro SPF con política -all"
    T[rec_harden_spf]="Endurecer SPF: migrar a -all"
    T[rec_implement_dmarc]="Implementar DMARC (empezar con p=none + rua)"
    T[rec_dmarc_none_up]="DMARC: evolucionar none → quarantine → reject"
    T[rec_dmarc_quar_up]="DMARC: evolucionar quarantine → reject"
    T[rec_enable_dnssec]="Habilitar DNSSEC para proteger integridad DNS"
    T[rec_implement_dane]="Tras DNSSEC, implementar DANE/TLSA en MX"
    T[rec_implement_mtasts]="Implementar MTA-STS para forzar TLS en tránsito"
    T[rec_add_tlsrpt]="Añadir TLS-RPT para recibir reportes de fallos TLS"
    T[rec_consider_bimi]="Considerar BIMI para mostrar logo de marca en bandejas"
    T[rec_configure_mx]="Configurar registros MX para recibir correo"
}

load_strings_en() {
    # ── General ──
    T[error]="Error"
    T[missing_dig]="Missing 'dig' command."
    T[install_with]="Install with:"
    T[enter_domain]="Enter the domain to audit: "
    T[invalid_domain]="'%s' does not look like a valid domain."
    T[no_dns_records]="The domain '%s' has no DNS records."
    T[check_typo]="Is it spelled correctly? Check for typos."
    T[audit_cancelled]="Audit cancelled."
    T[continue_anyway]="Continue with the audit anyway? [y/N]: "

    # ── Banner ──
    T[banner_title]="            EMAIL AUTHENTICATION AUDIT"
    T[banner_domain]="Domain"
    T[banner_date]="Date"
    T[banner_checks]="Checks"
    T[banner_extras]="Extras"
    T[banner_extras_none]="none"
    T[banner_checks_list]="MX · SPF · DKIM · DMARC · DANE/TLSA"
    T[banner_checks_list2]="MTA-STS · TLS-RPT · BIMI · TLS · Subdomains"

    # ── 1. MX ──
    T[mx_title]="1. MX (Mail eXchange)"
    T[mx_desc1]="Servers responsible for receiving email for the domain."
    T[mx_desc2]="Without MX records the domain cannot receive email. Priority"
    T[mx_desc3]="(lower number = preferred) determines delivery order."
    T[mx_not_found]="No MX records found"
    T[mx_no_receive]="This domain cannot receive email"
    T[mx_found]="MX servers found:"
    T[mx_priority]="PRIORITY"
    T[mx_server]="SERVER"
    T[mx_provider]="Detected provider"
    T[mx_provider_unknown]="Unidentified"

    # ── 2. SPF ──
    T[spf_title]="2. SPF (Sender Policy Framework)"
    T[spf_desc1]="Defines which IP servers are allowed to send email on behalf"
    T[spf_desc2]="of this domain. Without SPF, any server could send email"
    T[spf_desc3]="impersonating the domain (spoofing). RFC 7208."
    T[spf_not_found]="No SPF record found"
    T[spf_vulnerable]="Vulnerable to spoofing"
    T[spf_found]="Record found:"
    T[spf_uses_redirect]="Uses"
    T[spf_delegated]="Delegated SPF"
    T[spf_inherited_strict]="Inherited policy: STRICT (-all)"
    T[spf_inherited_soft]="Inherited policy: SOFT (~all)"
    T[spf_inherited_unknown]="Inherited policy not clearly determined"
    T[spf_redirect_fail]="Could not resolve SPF for the redirect domain"
    T[spf_strict]="STRICT (-all) — rejects unauthorized email"
    T[spf_soft]="SOFT (~all) — marks as suspicious, does not reject"
    T[spf_neutral]="NEUTRAL (?all) — no action"
    T[spf_open]="OPEN (+all) — anyone can spoof!"
    T[spf_no_all]="No explicit 'all' mechanism detected"
    T[spf_policy]="Policy"
    T[spf_lookups_exceed]="DNS lookups: %s/10 — exceeds RFC 7208"
    T[spf_lookups_near]="DNS lookups: %s/10 — close to the limit"
    T[spf_lookups_ok]="DNS lookups: %s/10"

    # ── 3. DKIM ──
    T[dkim_title]="3. DKIM (DomainKeys Identified Mail)"
    T[dkim_desc1]="Cryptographic signature in message headers that allows the"
    T[dkim_desc2]="receiver to verify the email was not altered in transit"
    T[dkim_desc3]="and truly comes from the signing domain. RFC 6376."
    T[dkim_found]="DKIM records found:"
    T[dkim_selector]="Selector"
    T[dkim_present]="Present"
    T[dkim_none]="No DKIM records in common selectors"
    T[dkim_custom]="May use a custom selector not tested"
    T[dkim_manual]="Manual test: dig TXT <selector>._domainkey.%s"
    T[dkim_total]="Total: %s DKIM selector(s) verified"

    # ── 4. DMARC ──
    T[dmarc_title]="4. DMARC (Domain-based Message Authentication, Reporting & Conformance)"
    T[dmarc_desc1]="Policy that unifies SPF and DKIM: tells receivers what to do"
    T[dmarc_desc2]="when a message fails authentication (reject, quarantine"
    T[dmarc_desc3]="or just monitor). Also enables reporting. RFC 7489."
    T[dmarc_not_found]="No DMARC record found"
    T[dmarc_no_instructions]="No instructions for unauthenticated email"
    T[dmarc_found]="Record found:"
    T[dmarc_delegated]="delegated via CNAME →"
    T[dmarc_policy]="Policy"
    T[dmarc_reject]="REJECT — rejects unauthenticated email"
    T[dmarc_quarantine]="QUARANTINE — sends to spam"
    T[dmarc_none]="NONE — monitor only, no active protection"
    T[dmarc_unknown_policy]="Unrecognized policy"
    T[dmarc_subdomains]="Subdomains (sp)"
    T[dmarc_pct]="Applied to only %s%% of email (target: 100%%)"
    T[dmarc_reports]="Reports:"
    T[dmarc_rua_ok]="Aggregate (rua)"
    T[dmarc_rua_missing]="No aggregate reports (rua)"
    T[dmarc_ruf_ok]="Forensic  (ruf)"
    T[dmarc_ruf_missing]="No forensic reports (ruf) — optional"

    # ── 5. DANE/TLSA ──
    T[dane_title]="5. DANE/TLSA (DNS-based Authentication of Named Entities)"
    T[dane_desc1]="Binds TLS certificates directly to DNS records, avoiding"
    T[dane_desc2]="sole reliance on CAs. Requires DNSSEC to guarantee"
    T[dane_desc3]="the integrity of TLSA records. RFC 6698 / RFC 7672."
    T[dane_dnssec_validated]="DNSSEC: Validated (AD flag present)"
    T[dane_dnssec_dnskey]="DNSSEC: DNSKEY found, no AD validation"
    T[dane_dnssec_resolver]="May depend on the resolver used"
    T[dane_dnssec_disabled]="DNSSEC: Not enabled"
    T[dane_dnssec_required]="DANE requires DNSSEC to work"
    T[dane_no_mx]="No MX servers — cannot verify TLSA"
    T[dane_tlsa_header]="TLSA records (port 25/SMTP) per MX server:"
    T[dane_no_tlsa]="No TLSA"
    T[dane_starttls_supported]="STARTTLS: Supported"
    T[dane_starttls_no]="STARTTLS: Not advertised in EHLO"
    T[dane_starttls_noresponse]="STARTTLS: No response on port 25"
    T[dane_summary]="DANE/TLSA Summary:"
    T[dane_mx_with_tlsa]="MX servers with TLSA"
    T[dane_tlsa_no_dnssec]="TLSA found but DNSSEC not validated"
    T[dane_no_tlsa_any]="No TLSA records on any MX server"
    T[dane_dnssec_active]="DNSSEC active: good time to implement DANE"
    T[dane_enable_dnssec]="Enable DNSSEC first, then add TLSA"
    T[dane_starttls_verified]="STARTTLS verified on %s server(s)"
    T[dane_use_ca]="CA constraint (PKIX-TA)"
    T[dane_use_service]="Service cert (PKIX-EE)"
    T[dane_use_trust]="Trust anchor (DANE-TA)"
    T[dane_use_domain]="Domain cert (DANE-EE)"
    T[dane_use_unknown]="Unknown"
    T[dane_sel_full]="Full cert"
    T[dane_sel_pubkey]="Public key"
    T[dane_sel_unknown]="Unknown"
    T[dane_match_unknown]="Unknown"

    # ── 6. MTA-STS ──
    T[mtasts_title]="6. MTA-STS (SMTP MTA Strict Transport Security)"
    T[mtasts_desc1]="Allows the domain to declare that its MX servers support TLS"
    T[mtasts_desc2]="and that senders must refuse delivery if a secure TLS"
    T[mtasts_desc3]="connection cannot be established. Complements DANE without"
    T[mtasts_desc4]="requiring DNSSEC. RFC 8461."
    T[mtasts_not_found]="No DNS record found for MTA-STS"
    T[mtasts_no_protection]="No protection against TLS downgrade in SMTP"
    T[mtasts_bad_record]="TXT record found but does not contain v=STSv1"
    T[mtasts_found]="DNS record found:"
    T[mtasts_policy_id]="Policy ID"
    T[mtasts_downloading]="Downloading policy from HTTPS..."
    T[mtasts_download_fail]="Could not download"
    T[mtasts_dns_ok_no_policy]="DNS record exists but policy is not accessible"
    T[mtasts_check_resolve]="Verify that mta-sts.%s resolves and has HTTPS"
    T[mtasts_downloaded]="Policy downloaded successfully:"
    T[mtasts_mode_enforce]="Mode: ENFORCE — rejects delivery without valid TLS"
    T[mtasts_mode_testing]="Mode: TESTING — reports failures but delivers anyway"
    T[mtasts_mode_none]="Mode: NONE — disables the policy"
    T[mtasts_mode_unknown]="Mode: %s — unrecognized"
    T[mtasts_maxage]="Validity (max_age)"
    T[mtasts_maxage_low]="max_age too low (<1 day). Recommended: ≥604800 (1 week)"
    T[mtasts_mx_authorized]="Authorized MX servers:"
    T[mtasts_install_curl]="Install 'curl' to verify the full HTTPS policy"
    T[mtasts_dns_only]="Only the DNS record was verified (step 1 of 2)"
    T[mtasts_days]="days"

    # ── 7. TLS-RPT ──
    T[tlsrpt_title]="7. TLS-RPT (SMTP TLS Reporting)"
    T[tlsrpt_desc1]="Allows receiving reports when other servers have problems"
    T[tlsrpt_desc2]="establishing TLS connections with your MX. Essential to detect"
    T[tlsrpt_desc3]="MTA-STS or DANE failures. Without TLS-RPT failures are invisible."
    T[tlsrpt_desc4]="RFC 8460."
    T[tlsrpt_not_found]="No TLS-RPT record found"
    T[tlsrpt_no_reports]="You won't receive TLS failure reports from other servers"
    T[tlsrpt_bad_record]="TXT record found but does not contain v=TLSRPTv1"
    T[tlsrpt_found]="Record found:"
    T[tlsrpt_destinations]="Report destinations:"

    # ── 8. BIMI ──
    T[bimi_title]="8. BIMI (Brand Indicators for Message Identification)"
    T[bimi_desc1]="Allows displaying the brand logo next to the sender in"
    T[bimi_desc2]="compatible inboxes (Gmail, Yahoo, Apple Mail...)."
    T[bimi_desc3]="Requires DMARC with p=quarantine or p=reject. Optionally"
    T[bimi_desc4]="a VMC (Verified Mark Certificate) can be included for"
    T[bimi_desc5]="greater trust. RFC pending (draft adopted by multiple ISPs)."
    T[bimi_not_found]="No BIMI record found"
    T[bimi_optional]="Optional but recommended if DMARC is at enforce/quarantine"
    T[bimi_bad_record]="TXT record found but does not contain v=BIMI1"
    T[bimi_found]="BIMI record found:"
    T[bimi_logo_accessible]="Logo accessible (HTTP %s)"
    T[bimi_logo_not_accessible]="Logo not accessible (HTTP %s)"
    T[bimi_no_logo]="No logo URL found (parameter l=)"
    T[bimi_vmc_present]="Verified mark certificate present"
    T[bimi_no_vmc]="No VMC (a=) — logo may not display in all clients"

    # ── 9. TLS Certs ──
    T[tls_title]="9. MX Server TLS Certificates"
    T[tls_desc1]="Verifies the TLS certificate presented by each MX server when"
    T[tls_desc2]="negotiating STARTTLS on port 25. An expired, self-signed or"
    T[tls_desc3]="hostname-mismatched certificate enables MitM attacks."
    T[tls_no_openssl]="openssl not available — skipping certificate verification"
    T[tls_install_openssl]="Install with: apt install openssl / brew install openssl"
    T[tls_no_mx]="No MX servers — nothing to verify"
    T[tls_checking_ports]="Checking SMTP port accessibility..."
    T[tls_port_open]="Port %s accessible on %s"
    T[tls_port_blocked]="Port %s blocked or no response"
    T[tls_no_smtp]="No SMTP ports accessible (25, 587, 465)"
    T[tls_isp_blocking]="Your ISP or firewall is blocking outbound SMTP traffic."
    T[tls_common_home]="This is common on home networks and cloud providers."
    T[tls_check_online]="Check TLS certificates online:"
    T[tls_ssl_tools]="Certificate, STARTTLS, PFS, DANE, Heartbleed"
    T[tls_checktls]="Full SMTP conversation, MTA-STS, DANE"
    T[tls_hardenize]="Full domain security analysis"
    T[tls_mxtoolbox]="SMTP TLS, certificates, MX diagnostics"
    T[tls_internetnl]="Dutch government standard test"
    T[tls_local_tip]="To run this check locally:"
    T[tls_vps_tip]="Use a VPS with port 25 open (Hetzner, OVH...)"
    T[tls_vpn_tip]="Use a VPN that doesn't filter SMTP"
    T[tls_network_tip]="Run from a network without egress restrictions"
    T[tls_no_cert]="Could not obtain TLS certificate"
    T[tls_ports_tried]="Ports tried: 25, 587, 465 — all inaccessible"
    T[tls_firewall]="Network/firewall blocking outbound SMTP, or server has no TLS"
    T[tls_manual]="Manual test: openssl s_client -starttls smtp -connect %s:25"
    T[tls_port]="Port"
    T[tls_subject]="Subject"
    T[tls_issuer]="Issuer"
    T[tls_obsolete]="obsolete and insecure"
    T[tls_expired]="Certificate EXPIRED %s days ago"
    T[tls_expires_urgent]="Expires in %s days — renew urgently"
    T[tls_expires_soon]="Expires in %s days"
    T[tls_valid]="Valid for %s more days (until %s)"
    T[tls_hostname_ok]="Hostname matches certificate"
    T[tls_hostname_cn_ok]="Hostname matches certificate CN"
    T[tls_hostname_mismatch]="Hostname does not match SANs/CN of certificate"
    T[tls_self_signed]="SELF-SIGNED certificate"
    T[tls_summary]="TLS Summary:"
    T[tls_certs_valid]="valid and current certificates"

    # ── 10. Subdomain protection ──
    T[sub_title]="10. Subdomain spoofing protection"
    T[sub_desc1]="Attackers can spoof email from subdomains like"
    T[sub_desc2]="mail.domain.com or smtp.domain.com if they lack their own"
    T[sub_desc3]="restrictive SPF. A 'null SPF' (v=spf1 -all) on subdomains"
    T[sub_desc4]="that don't send email blocks this attack vector."
    T[sub_subdomain]="SUBDOMAIN"
    T[sub_status]="STATUS"
    T[sub_vulnerable]="Vulnerable"
    T[sub_protected]="Protected"
    T[sub_restrictive]="Restrictive"
    T[sub_softfail]="Softfail"
    T[sub_review]="Review"
    T[sub_none_found]="No common subdomains found with DNS records"
    T[sub_none_normal]="This is normal if the domain doesn't use mail subdomains"
    T[sub_all_protected]="%s/%s subdomains protected"
    T[sub_unprotected]="%s subdomain(s) without SPF protection"
    T[sub_add_record]="Add record: v=spf1 -all"
    T[sub_dmarc_sp]="Root domain DMARC includes sp=%s for subdomains"
    T[sub_inherit_reject]="Subdomains inherit reject policy"
    T[sub_inherit_quarantine]="Subdomains inherit quarantine policy"
    T[sub_inherit_other]="Subdomains inherit %s policy"

    # ── No-mail warning ──
    T[nomail_title]="This domain does not appear to have email configured"
    T[nomail_no_mx]="No MX records found for"
    T[nomail_causes]="Possible causes:"
    T[nomail_cause1]="Typo in the domain name"
    T[nomail_cause2]="The domain does not use email"
    T[nomail_cause3]="MX records have not propagated yet"

    # ── Summary ──
    T[summary_title]="FINAL RESULT"
    T[summary_level]="Security level"
    T[summary_good]="GOOD"
    T[summary_improvable]="IMPROVABLE"
    T[summary_poor]="POOR"
    T[summary_checks]="Check summary:"
    T[summary_recommendations]="Recommendations:"
    T[summary_excellent]="Excellent configuration. Review periodically."
    T[summary_improve]="Improve this audit:"
    T[summary_install_openssl]="Install openssl to verify TLS certificates"
    T[summary_install_curl]="Install curl to validate MTA-STS and BIMI policies"
    T[summary_points]="points"

    # ── Recommendation strings ──
    T[rec_create_spf]="Create SPF record with -all policy"
    T[rec_harden_spf]="Harden SPF: migrate to -all"
    T[rec_implement_dmarc]="Implement DMARC (start with p=none + rua)"
    T[rec_dmarc_none_up]="DMARC: evolve none → quarantine → reject"
    T[rec_dmarc_quar_up]="DMARC: evolve quarantine → reject"
    T[rec_enable_dnssec]="Enable DNSSEC to protect DNS integrity"
    T[rec_implement_dane]="After DNSSEC, implement DANE/TLSA on MX"
    T[rec_implement_mtasts]="Implement MTA-STS to enforce TLS in transit"
    T[rec_add_tlsrpt]="Add TLS-RPT to receive TLS failure reports"
    T[rec_consider_bimi]="Consider BIMI to display brand logo in inboxes"
    T[rec_configure_mx]="Configure MX records to receive email"
}

# Helper to get a translated string (with optional printf args)
t() {
    local key="$1"
    shift
    local str="${T[$key]:-MISSING:$key}"
    if [[ $# -gt 0 ]]; then
        printf "$str" "$@"
    else
        printf '%s' "$str"
    fi
}

# ─── Box utilities ────────────────────────────────────────────────────
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

# ─── Dependency check ─────────────────────────────────────────────────
comprobar_dependencias() {
    if ! command -v dig &>/dev/null; then
        printf "${RED}$(t error):${NC} $(t missing_dig)\n"
        printf "$(t install_with)\n"
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

# ─── Validate domain format ──────────────────────────────────────────
validar_dominio() {
    if [[ ! "$1" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$ ]]; then
        printf "${RED}$(t error):${NC} $(t invalid_domain "$1")\n"
        exit 1
    fi
}

# ─── Verify domain exists in DNS ─────────────────────────────────────
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
        printf "${RED}  ✗ $(t no_dns_records "$dominio")${NC}\n"
        printf "${RED}  $(t check_typo)${NC}\n"
        printf "${RED}══════════════════════════════════════════════════════════════${NC}\n"
        printf "\n"
        exit 1
    fi
}

# ─── Banner ───────────────────────────────────────────────────────────
mostrar_banner() {
    local dominio="$1"
    local fecha
    fecha=$(date '+%Y-%m-%d %H:%M:%S')

    local extras=""
    if [[ "$TIENE_OPENSSL" == true ]]; then extras+="openssl "; fi
    if [[ "$TIENE_CURL" == true ]]; then extras+="curl "; fi
    if command -v nc &>/dev/null; then extras+="nc "; fi
    if [[ -z "$extras" ]]; then extras="$(t banner_extras_none)"; fi

    printf "\n"
    printf "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}\n"
    linea_vacia
    linea_recuadro "${BOLD}$(t banner_title)${NC}"
    linea_vacia
    printf "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}\n"
    linea_recuadro "  $(t banner_domain):  ${dominio}"
    linea_recuadro "  $(t banner_date):    ${fecha}"
    linea_recuadro "  $(t banner_checks):   $(t banner_checks_list)"
    linea_recuadro "            $(t banner_checks_list2)"
    linea_recuadro "  $(t banner_extras):   ${extras}"
    printf "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}\n"
    printf "\n"
}

# ═════════════════════════════════════════════════════════════════════
# 1. MX
# ═════════════════════════════════════════════════════════════════════
auditar_mx() {
    local dominio="$1"
    seccion_inicio
    L "${BOLD}$(t mx_title)${NC}"
    L "${DIM}$(t mx_desc1)${NC}"
    L "${DIM}$(t mx_desc2)${NC}"
    L "${DIM}$(t mx_desc3)${NC}"
    LV

    local mx
    mx=$(safe_dig +short MX "$dominio" | sort -n || true)

    if [[ -z "$mx" ]]; then
        L " ${FAIL} $(t mx_not_found)"
        L "   ${YELLOW}→ $(t mx_no_receive)${NC}"
        sumar_puntos 0 2
        TIENE_MX=false
        seccion_fin
        return
    fi

    TIENE_MX=true

    L " ${OK} $(t mx_found)"
    LV
    L "   ${DIM}$(printf '%-12s %-45s' "$(t mx_priority)" "$(t mx_server)")${NC}"
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
    L " $(t mx_provider): \c"

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
    elif echo "$mx" | grep -qi "cpanel\|whm"; then
        printf "${GREEN}cPanel Mail${NC}\n"
    elif echo "$mx" | grep -qi "plesk"; then
        printf "${GREEN}Plesk Mail${NC}\n"
    elif echo "$mx" | grep -qi "zimbra"; then
        printf "${GREEN}Zimbra${NC}\n"
    else
        local mx_host
        mx_host=$(echo "$mx" | head -1 | awk '{print $2}')
        printf "${YELLOW}$(t mx_provider_unknown)${NC} (${DIM}${mx_host}${NC})\n"
    fi
    seccion_fin
}

# ═════════════════════════════════════════════════════════════════════
# 2. SPF
# ═════════════════════════════════════════════════════════════════════
auditar_spf() {
    local dominio="$1"
    seccion_inicio
    L "${BOLD}$(t spf_title)${NC}"
    L "${DIM}$(t spf_desc1)${NC}"
    L "${DIM}$(t spf_desc2)${NC}"
    L "${DIM}$(t spf_desc3)${NC}"
    LV

    local spf
    spf=$(safe_dig +short TXT "$dominio" | grep -i "v=spf1" || true)

    if [[ -z "$spf" ]]; then
        L " ${FAIL} $(t spf_not_found)"
        L "   ${YELLOW}→ $(t spf_vulnerable)${NC}"
        sumar_puntos 0 3
        seccion_fin
        return
    fi

    L " ${OK} $(t spf_found)"
    L "   ${CYAN}${spf}${NC}"
    LV

    local tiene_redirect=""
    tiene_redirect=$(echo "$spf" | grep -oP 'redirect=\K[^ "]+' || true)

    if [[ -n "$tiene_redirect" ]]; then
        L " ${INFO} $(t spf_uses_redirect) ${CYAN}redirect=${tiene_redirect}${NC}"

        local spf_redir
        spf_redir=$(safe_dig +short TXT "$tiene_redirect" | grep -i "v=spf1" || true)
        if [[ -n "$spf_redir" ]]; then
            local spf_redir_limpio
            spf_redir_limpio=$(printf '%s' "$spf_redir" | tr -d '"')
            if [[ ${#spf_redir_limpio} -gt 70 ]]; then
                spf_redir_limpio="${spf_redir_limpio:0:67}..."
            fi
            L "   $(t spf_delegated): ${DIM}${spf_redir_limpio}${NC}"

            if echo "$spf_redir" | grep -q "\-all"; then
                L " ${OK} $(t spf_inherited_strict)"
                sumar_puntos 3 3
            elif echo "$spf_redir" | grep -q "\~all"; then
                L " ${WARN} $(t spf_inherited_soft)"
                sumar_puntos 2 3
            else
                L " ${WARN} $(t spf_inherited_unknown)"
                sumar_puntos 1 3
            fi
        else
            L " ${WARN} $(t spf_redirect_fail)"
            sumar_puntos 1 3
        fi
    elif echo "$spf" | grep -q "\-all"; then
        L " ${OK} $(t spf_policy): ${GREEN}$(t spf_strict)${NC}"
        sumar_puntos 3 3
    elif echo "$spf" | grep -q "\~all"; then
        L " ${WARN} $(t spf_policy): ${YELLOW}$(t spf_soft)${NC}"
        sumar_puntos 2 3
    elif echo "$spf" | grep -q "\?all"; then
        L " ${WARN} $(t spf_policy): ${YELLOW}$(t spf_neutral)${NC}"
        sumar_puntos 1 3
    elif echo "$spf" | grep -q "+all"; then
        L " ${FAIL} $(t spf_policy): ${RED}$(t spf_open)${NC}"
        sumar_puntos 0 3
    else
        L " ${WARN} $(t spf_no_all)"
        sumar_puntos 1 3
    fi

    local lookups
    lookups=$(echo "$spf" | grep -oE '(include:|a:|mx:|ptr:|redirect=)' | wc -l | tr -d ' ')
    if [[ "$lookups" -gt 10 ]]; then
        L " ${FAIL} $(t spf_lookups_exceed "$lookups")"
    elif [[ "$lookups" -gt 7 ]]; then
        L " ${WARN} $(t spf_lookups_near "$lookups")"
    else
        L " ${OK} $(t spf_lookups_ok "$lookups")"
    fi
    seccion_fin
}

# ═════════════════════════════════════════════════════════════════════
# 3. DKIM
# ═════════════════════════════════════════════════════════════════════
auditar_dkim() {
    local dominio="$1"
    seccion_inicio
    L "${BOLD}$(t dkim_title)${NC}"
    L "${DIM}$(t dkim_desc1)${NC}"
    L "${DIM}$(t dkim_desc2)${NC}"
    L "${DIM}$(t dkim_desc3)${NC}"
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
                L " ${OK} $(t dkim_found)"
            fi
            L "   $(t dkim_selector): ${CYAN}$(printf '%-15s' "$selector")${NC} → ${GREEN}$(t dkim_present)${NC}"
            encontrados=$((encontrados + 1))
        fi
    done

    if [[ $encontrados -eq 0 ]]; then
        L " ${WARN} $(t dkim_none)"
        L "   ${YELLOW}→ $(t dkim_custom)${NC}"
        L "   ${DIM}$(t dkim_manual "$dominio")${NC}"
        sumar_puntos 0 2
    else
        L " ${OK} $(t dkim_total "$encontrados")"
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
    L "${BOLD}$(t dmarc_title)${NC}"
    L "${DIM}$(t dmarc_desc1)${NC}"
    L "${DIM}$(t dmarc_desc2)${NC}"
    L "${DIM}$(t dmarc_desc3)${NC}"
    LV

    local dmarc_raw
    dmarc_raw=$(safe_dig +noall +answer TXT "_dmarc.${dominio}" || true)

    local dmarc
    dmarc=$(echo "$dmarc_raw" | grep -oP '"v=DMARC1[^"]*"' | head -1 || true)

    if [[ -z "$dmarc" ]]; then
        L " ${FAIL} $(t dmarc_not_found)"
        L "   ${YELLOW}→ $(t dmarc_no_instructions)${NC}"
        sumar_puntos 0 3
        seccion_fin
        return
    fi

    local cname_target
    cname_target=$(echo "$dmarc_raw" | awk '/CNAME/{print $NF}' | head -1 || true)

    L " ${OK} $(t dmarc_found)"
    if [[ -n "$cname_target" ]]; then
        L "   ${DIM}($(t dmarc_delegated) ${cname_target})${NC}"
    fi
    L "   ${CYAN}${dmarc}${NC}"
    LV

    local politica
    politica=$(echo "$dmarc" | grep -oP 'p=\K[^;]+' | tr -d '"' | head -1 || true)
    case "$politica" in
        reject)
            L " ${OK} $(t dmarc_policy): ${GREEN}$(t dmarc_reject)${NC}"
            sumar_puntos 3 3
            ;;
        quarantine)
            L " ${WARN} $(t dmarc_policy): ${YELLOW}$(t dmarc_quarantine)${NC}"
            sumar_puntos 2 3
            ;;
        none)
            L " ${WARN} $(t dmarc_policy): ${YELLOW}$(t dmarc_none)${NC}"
            sumar_puntos 1 3
            ;;
        *)
            L " ${WARN} $(t dmarc_unknown_policy): '${politica}'"
            sumar_puntos 0 3
            ;;
    esac

    local sub_politica
    sub_politica=$(echo "$dmarc" | grep -oP 'sp=\K[^;]+' | tr -d '"' | head -1 || true)
    if [[ -n "$sub_politica" ]]; then
        L "   $(t dmarc_subdomains): ${CYAN}${sub_politica}${NC}"
    fi

    local pct
    pct=$(echo "$dmarc" | grep -oP 'pct=\K[0-9]+' | head -1 || true)
    if [[ -n "$pct" ]] && [[ "$pct" -lt 100 ]]; then
        L " ${WARN} $(t dmarc_pct "$pct")"
    fi

    local rua ruf
    rua=$(echo "$dmarc" | grep -oP 'rua=\K[^;]+' | tr -d '"' | head -1 || true)
    ruf=$(echo "$dmarc" | grep -oP 'ruf=\K[^;]+' | tr -d '"' | head -1 || true)
    LV
    L " $(t dmarc_reports)"
    if [[ -n "$rua" ]]; then
        L "   ${OK} $(t dmarc_rua_ok): ${CYAN}${rua}${NC}"
    else
        L "   ${WARN} $(t dmarc_rua_missing)"
    fi
    if [[ -n "$ruf" ]]; then
        L "   ${OK} $(t dmarc_ruf_ok): ${CYAN}${ruf}${NC}"
    else
        L "   ${INFO} $(t dmarc_ruf_missing)"
    fi
    seccion_fin
}

# ═════════════════════════════════════════════════════════════════════
# 5. DANE / TLSA
# ═════════════════════════════════════════════════════════════════════
auditar_dane() {
    local dominio="$1"
    seccion_inicio
    L "${BOLD}$(t dane_title)${NC}"
    L "${DIM}$(t dane_desc1)${NC}"
    L "${DIM}$(t dane_desc2)${NC}"
    L "${DIM}$(t dane_desc3)${NC}"
    LV

    local dnssec_ok=false
    local dnssec_check
    dnssec_check=$(safe_dig +dnssec +short DNSKEY "$dominio" || true)

    if [[ -n "$dnssec_check" ]]; then
        local ad_check
        ad_check=$(safe_dig +dnssec "$dominio" A | grep -c "flags:.*ad" || true)
        if [[ "$ad_check" -gt 0 ]]; then
            L " ${OK} ${GREEN}$(t dane_dnssec_validated)${NC}"
            dnssec_ok=true
        else
            L " ${WARN} ${YELLOW}$(t dane_dnssec_dnskey)${NC}"
            L "   ${DIM}$(t dane_dnssec_resolver)${NC}"
            dnssec_ok=true
        fi
    else
        L " ${FAIL} ${RED}$(t dane_dnssec_disabled)${NC}"
        L "   ${YELLOW}→ $(t dane_dnssec_required)${NC}"
    fi

    LV

    if [[ ${#MX_SERVERS[@]} -eq 0 ]]; then
        L " ${WARN} $(t dane_no_mx)"
        sumar_puntos 0 2
        seccion_fin
        return
    fi

    local tlsa_encontrados=0
    local tlsa_total=0
    local starttls_count=0

    L " $(t dane_tlsa_header)"
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
                    0) uso_desc="$(t dane_use_ca)" ;;
                    1) uso_desc="$(t dane_use_service)" ;;
                    2) uso_desc="$(t dane_use_trust)" ;;
                    3) uso_desc="$(t dane_use_domain)" ;;
                    *) uso_desc="$(t dane_use_unknown)" ;;
                esac

                local sel_desc
                case "$selector" in
                    0) sel_desc="$(t dane_sel_full)" ;;
                    1) sel_desc="$(t dane_sel_pubkey)" ;;
                    *) sel_desc="$(t dane_sel_unknown)" ;;
                esac

                local match_desc
                case "$matching" in
                    0) match_desc="Exact" ;;
                    1) match_desc="SHA-256" ;;
                    2) match_desc="SHA-512" ;;
                    *) match_desc="$(t dane_match_unknown)" ;;
                esac

                L "      Uso: ${GREEN}${usage}${NC} (${uso_desc})"
                L "      Selector: ${selector} (${sel_desc}) · Match: ${matching} (${match_desc})"
            done <<< "$tlsa"
        else
            L "   ${FAIL} ${CYAN}${mx_server}${NC} → $(t dane_no_tlsa)"
        fi

        if command -v timeout &>/dev/null && command -v nc &>/dev/null; then
            local smtp_banner
            smtp_banner=$(timeout 5 bash -c "echo 'EHLO test' | nc -w3 \"${mx_server}\" 25" 2>/dev/null || true)
            if [[ -n "$smtp_banner" ]] && echo "$smtp_banner" | grep -qi "STARTTLS"; then
                L "      ${OK} ${GREEN}$(t dane_starttls_supported)${NC}"
                starttls_count=$((starttls_count + 1))
            elif [[ -n "$smtp_banner" ]]; then
                L "      ${WARN} ${YELLOW}$(t dane_starttls_no)${NC}"
            else
                L "      ${INFO} ${DIM}$(t dane_starttls_noresponse)${NC}"
            fi
        fi
        LV
    done

    L " $(t dane_summary)"
    if [[ $tlsa_encontrados -gt 0 ]] && [[ "$dnssec_ok" == true ]]; then
        L "   ${OK} ${GREEN}${tlsa_encontrados}/${tlsa_total}${NC} $(t dane_mx_with_tlsa)"
        if [[ $tlsa_encontrados -eq $tlsa_total ]]; then
            sumar_puntos 2 2
        else
            sumar_puntos 1 2
        fi
    elif [[ $tlsa_encontrados -gt 0 ]]; then
        L "   ${WARN} $(t dane_tlsa_no_dnssec)"
        sumar_puntos 1 2
    else
        L "   ${FAIL} $(t dane_no_tlsa_any)"
        if [[ "$dnssec_ok" == true ]]; then
            L "   ${YELLOW}→ $(t dane_dnssec_active)${NC}"
        else
            L "   ${YELLOW}→ $(t dane_enable_dnssec)${NC}"
        fi
        sumar_puntos 0 2
    fi

    if [[ $starttls_count -gt 0 ]]; then
        L "   ${OK} $(t dane_starttls_verified "$starttls_count")"
    fi
    seccion_fin
}

# ═════════════════════════════════════════════════════════════════════
# 6. MTA-STS
# ═════════════════════════════════════════════════════════════════════
auditar_mta_sts() {
    local dominio="$1"
    seccion_inicio
    L "${BOLD}$(t mtasts_title)${NC}"
    L "${DIM}$(t mtasts_desc1)${NC}"
    L "${DIM}$(t mtasts_desc2)${NC}"
    L "${DIM}$(t mtasts_desc3)${NC}"
    L "${DIM}$(t mtasts_desc4)${NC}"
    LV

    local mta_sts_dns
    mta_sts_dns=$(safe_dig +short TXT "_mta-sts.${dominio}" | tr -d '"' || true)

    if [[ -z "$mta_sts_dns" ]]; then
        L " ${FAIL} $(t mtasts_not_found)"
        L "   ${DIM}_mta-sts.${dominio} TXT → (vacío)${NC}"
        L "   ${YELLOW}→ $(t mtasts_no_protection)${NC}"
        sumar_puntos 0 2
        seccion_fin
        return
    fi

    if ! echo "$mta_sts_dns" | grep -qi "v=STSv1"; then
        L " ${WARN} $(t mtasts_bad_record)"
        L "   ${CYAN}${mta_sts_dns}${NC}"
        sumar_puntos 0 2
        seccion_fin
        return
    fi

    L " ${OK} $(t mtasts_found)"
    L "   ${CYAN}${mta_sts_dns}${NC}"

    local sts_id
    sts_id=$(echo "$mta_sts_dns" | grep -oP 'id=\K[^;[:space:]]+' || true)
    if [[ -n "$sts_id" ]]; then
        L "   $(t mtasts_policy_id): ${CYAN}${sts_id}${NC}"
    fi

    LV

    if [[ "$TIENE_CURL" == true ]]; then
        L " $(t mtasts_downloading)"
        local policy_url="https://mta-sts.${dominio}/.well-known/mta-sts.txt"
        local policy
        policy=$(curl -sS --max-time 10 --location "$policy_url" 2>/dev/null || true)

        if [[ -z "$policy" ]]; then
            L "   ${WARN} $(t mtasts_download_fail) ${DIM}${policy_url}${NC}"
            L "   ${YELLOW}→ $(t mtasts_dns_ok_no_policy)${NC}"
            L "   ${YELLOW}→ $(t mtasts_check_resolve "$dominio")${NC}"
            sumar_puntos 1 2
        else
            L "   ${OK} $(t mtasts_downloaded)"
            LV

            local mode max_age mx_lines
            mode=$(echo "$policy" | grep -oP 'mode:\s*\K\S+' | head -1 || true)
            max_age=$(echo "$policy" | grep -oP 'max_age:\s*\K[0-9]+' | head -1 || true)
            mx_lines=$(echo "$policy" | grep -oP 'mx:\s*\K\S+' || true)

            if [[ -n "$mode" ]]; then
                case "$mode" in
                    enforce)
                        L "   ${OK} ${GREEN}$(t mtasts_mode_enforce)${NC}"
                        ;;
                    testing)
                        L "   ${WARN} ${YELLOW}$(t mtasts_mode_testing)${NC}"
                        ;;
                    none)
                        L "   ${WARN} ${YELLOW}$(t mtasts_mode_none)${NC}"
                        ;;
                    *)
                        L "   ${WARN} ${YELLOW}$(t mtasts_mode_unknown "$mode")${NC}"
                        ;;
                esac
            fi

            if [[ -n "$max_age" ]]; then
                local dias=$((max_age / 86400))
                L "   $(t mtasts_maxage): ${CYAN}${max_age}s${NC} (~${dias} $(t mtasts_days))"
                if [[ $max_age -lt 86400 ]]; then
                    L "   ${WARN} $(t mtasts_maxage_low)"
                fi
            fi

            if [[ -n "$mx_lines" ]]; then
                L "   $(t mtasts_mx_authorized)"
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
        L "   ${INFO} ${DIM}$(t mtasts_install_curl)${NC}"
        L "   ${DIM}$(t mtasts_dns_only)${NC}"
        sumar_puntos 1 2
    fi
    seccion_fin
}

# ═════════════════════════════════════════════════════════════════════
# 7. TLS-RPT
# ═════════════════════════════════════════════════════════════════════
auditar_tls_rpt() {
    local dominio="$1"
    seccion_inicio
    L "${BOLD}$(t tlsrpt_title)${NC}"
    L "${DIM}$(t tlsrpt_desc1)${NC}"
    L "${DIM}$(t tlsrpt_desc2)${NC}"
    L "${DIM}$(t tlsrpt_desc3)${NC}"
    L "${DIM}$(t tlsrpt_desc4)${NC}"
    LV

    local tlsrpt
    tlsrpt=$(safe_dig +short TXT "_smtp._tls.${dominio}" | tr -d '"' || true)

    if [[ -z "$tlsrpt" ]]; then
        L " ${FAIL} $(t tlsrpt_not_found)"
        L "   ${DIM}_smtp._tls.${dominio} TXT → (vacío)${NC}"
        L "   ${YELLOW}→ $(t tlsrpt_no_reports)${NC}"
        sumar_puntos 0 1
        seccion_fin
        return
    fi

    if ! echo "$tlsrpt" | grep -qi "v=TLSRPTv1"; then
        L " ${WARN} $(t tlsrpt_bad_record)"
        L "   ${CYAN}${tlsrpt}${NC}"
        sumar_puntos 0 1
        seccion_fin
        return
    fi

    L " ${OK} $(t tlsrpt_found)"
    L "   ${CYAN}${tlsrpt}${NC}"

    local rua
    rua=$(echo "$tlsrpt" | grep -oP 'rua=\K[^;]+' || true)
    if [[ -n "$rua" ]]; then
        LV
        L " $(t tlsrpt_destinations)"
        IFS=',' read -ra destinos <<< "$rua"
        for dest in "${destinos[@]}"; do
            dest=$(echo "$dest" | xargs)
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
# 8. BIMI
# ═════════════════════════════════════════════════════════════════════
auditar_bimi() {
    local dominio="$1"
    seccion_inicio
    L "${BOLD}$(t bimi_title)${NC}"
    L "${DIM}$(t bimi_desc1)${NC}"
    L "${DIM}$(t bimi_desc2)${NC}"
    L "${DIM}$(t bimi_desc3)${NC}"
    L "${DIM}$(t bimi_desc4)${NC}"
    L "${DIM}$(t bimi_desc5)${NC}"
    LV

    local bimi
    bimi=$(safe_dig +short TXT "default._bimi.${dominio}" | tr -d '"' || true)

    if [[ -z "$bimi" ]]; then
        L " ${INFO} $(t bimi_not_found)"
        L "   ${DIM}default._bimi.${dominio} TXT → (vacío)${NC}"
        L "   ${DIM}→ $(t bimi_optional)${NC}"
        sumar_puntos 0 1
        seccion_fin
        return
    fi

    if ! echo "$bimi" | grep -qi "v=BIMI1"; then
        L " ${WARN} $(t bimi_bad_record)"
        L "   ${CYAN}${bimi}${NC}"
        sumar_puntos 0 1
        seccion_fin
        return
    fi

    L " ${OK} $(t bimi_found)"
    L "   ${CYAN}${bimi}${NC}"
    LV

    local logo_url
    logo_url=$(echo "$bimi" | grep -oP 'l=\K[^;]+' || true)
    if [[ -n "$logo_url" ]]; then
        L "   Logo (SVG): ${CYAN}${logo_url}${NC}"

        if [[ "$TIENE_CURL" == true ]]; then
            local http_code
            http_code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "$logo_url" 2>/dev/null || echo "000")
            if [[ "$http_code" == "200" ]]; then
                L "   ${OK} $(t bimi_logo_accessible "$http_code")"
            else
                L "   ${WARN} $(t bimi_logo_not_accessible "$http_code")"
            fi
        fi
    else
        L "   ${WARN} $(t bimi_no_logo)"
    fi

    local vmc_url
    vmc_url=$(echo "$bimi" | grep -oP 'a=\K[^;]+' || true)
    if [[ -n "$vmc_url" ]]; then
        L "   VMC: ${CYAN}${vmc_url}${NC}"
        L "   ${OK} $(t bimi_vmc_present)"
    else
        L "   ${INFO} $(t bimi_no_vmc)"
    fi

    sumar_puntos 1 1
    seccion_fin
}

# ═════════════════════════════════════════════════════════════════════
# 9. TLS Certificates
# ═════════════════════════════════════════════════════════════════════
auditar_tls_certs() {
    local dominio="$1"
    seccion_inicio
    L "${BOLD}$(t tls_title)${NC}"
    L "${DIM}$(t tls_desc1)${NC}"
    L "${DIM}$(t tls_desc2)${NC}"
    L "${DIM}$(t tls_desc3)${NC}"
    LV

    if [[ "$TIENE_OPENSSL" != true ]]; then
        L " ${INFO} ${DIM}$(t tls_no_openssl)${NC}"
        L "   ${DIM}$(t tls_install_openssl)${NC}"
        seccion_fin
        return
    fi

    if [[ ${#MX_SERVERS[@]} -eq 0 ]]; then
        L " ${WARN} $(t tls_no_mx)"
        seccion_fin
        return
    fi

    local primer_mx="${MX_SERVERS[0]%.}"
    local smtp_accesible=false
    local puertos_test=(25 587 465)

    L " $(t tls_checking_ports)"
    for puerto_test in "${puertos_test[@]}"; do
        local test_ok=false
        if command -v nc &>/dev/null; then
            if nc -zw3 "$primer_mx" "$puerto_test" &>/dev/null; then
                test_ok=true
            fi
        elif command -v timeout &>/dev/null; then
            if timeout 3 bash -c "echo >/dev/tcp/${primer_mx}/${puerto_test}" &>/dev/null; then
                test_ok=true
            fi
        fi
        if [[ "$test_ok" == true ]]; then
            L "   ${OK} $(t tls_port_open "$puerto_test" "$primer_mx")"
            smtp_accesible=true
        else
            L "   ${FAIL} $(t tls_port_blocked "$puerto_test")"
        fi
    done
    LV

    if [[ "$smtp_accesible" == false ]]; then
        L " ${FAIL} ${RED}$(t tls_no_smtp)${NC}"
        L "   ${YELLOW}$(t tls_isp_blocking)${NC}"
        L "   ${YELLOW}$(t tls_common_home)${NC}"
        LV
        L " ${INFO} ${BOLD}$(t tls_check_online)${NC}"
        LV
        L "   ${CYAN}ssl-tools.net${NC} — $(t tls_ssl_tools)"
        L "   ${DIM}https://ssl-tools.net/mailservers/${dominio}${NC}"
        LV
        L "   ${CYAN}CheckTLS${NC} — $(t tls_checktls)"
        L "   ${DIM}https://www.checktls.com/TestReceiver${NC}"
        LV
        L "   ${CYAN}Hardenize${NC} — $(t tls_hardenize)"
        L "   ${DIM}https://www.hardenize.com/report/${dominio}${NC}"
        LV
        L "   ${CYAN}MXToolbox${NC} — $(t tls_mxtoolbox)"
        L "   ${DIM}https://mxtoolbox.com/SuperTool.aspx?action=smtp:${primer_mx}:25${NC}"
        LV
        L "   ${CYAN}Internet.nl${NC} — $(t tls_internetnl)"
        L "   ${DIM}https://internet.nl/mail/${dominio}${NC}"
        LV
        L "   ${DIM}$(t tls_local_tip)${NC}"
        L "   ${DIM} • $(t tls_vps_tip)${NC}"
        L "   ${DIM} • $(t tls_vpn_tip)${NC}"
        L "   ${DIM} • $(t tls_network_tip)${NC}"
        sumar_puntos 0 2
        seccion_fin
        return
    fi

    local certs_ok=0
    local certs_total=0

    for mx_server in "${MX_SERVERS[@]}"; do
        mx_server="${mx_server%.}"
        certs_total=$((certs_total + 1))

        L "   ${CYAN}${mx_server}${NC}"

        local cert_info=""
        local puerto_usado=""

        cert_info=$(echo "" | timeout 5 openssl s_client \
            -starttls smtp \
            -connect "${mx_server}:25" \
            -servername "${mx_server}" \
            2>/dev/null || true)

        if echo "$cert_info" | grep -q "BEGIN CERTIFICATE"; then
            puerto_usado="25 (STARTTLS)"
        fi

        if [[ -z "$puerto_usado" ]]; then
            cert_info=$(echo "" | timeout 5 openssl s_client \
                -starttls smtp \
                -connect "${mx_server}:587" \
                -servername "${mx_server}" \
                2>/dev/null || true)

            if echo "$cert_info" | grep -q "BEGIN CERTIFICATE"; then
                puerto_usado="587 (STARTTLS/submission)"
            fi
        fi

        if [[ -z "$puerto_usado" ]]; then
            cert_info=$(echo "" | timeout 5 openssl s_client \
                -connect "${mx_server}:465" \
                -servername "${mx_server}" \
                2>/dev/null || true)

            if echo "$cert_info" | grep -q "BEGIN CERTIFICATE"; then
                puerto_usado="465 (SMTPS/TLS)"
            fi
        fi

        if [[ -z "$puerto_usado" ]]; then
            L "      ${FAIL} $(t tls_no_cert)"
            L "      ${DIM}$(t tls_ports_tried)${NC}"
            L "      ${YELLOW}→ $(t tls_firewall)${NC}"
            L "      ${DIM}$(t tls_manual "$mx_server")${NC}"
            LV
            continue
        fi

        L "      $(t tls_port): ${GREEN}${puerto_usado}${NC}"

        local subject issuer
        subject=$(echo "$cert_info" | openssl x509 -noout -subject 2>/dev/null | sed 's/subject=//' || true)
        issuer=$(echo "$cert_info" | openssl x509 -noout -issuer 2>/dev/null | sed 's/issuer=//' || true)

        local sans
        sans=$(echo "$cert_info" | openssl x509 -noout -ext subjectAltName 2>/dev/null | grep -oP 'DNS:\K[^,]+' | tr '\n' ' ' || true)

        local not_before not_after
        not_before=$(echo "$cert_info" | openssl x509 -noout -startdate 2>/dev/null | sed 's/notBefore=//' || true)
        not_after=$(echo "$cert_info" | openssl x509 -noout -enddate 2>/dev/null | sed 's/notAfter=//' || true)

        local tls_version
        tls_version=$(echo "$cert_info" | grep -oP 'Protocol\s*:\s*\K\S+' | head -1 || true)

        if [[ -n "$subject" ]]; then
            L "      $(t tls_subject): ${DIM}${subject}${NC}"
        fi
        if [[ -n "$issuer" ]]; then
            local issuer_short
            issuer_short=$(echo "$issuer" | grep -oP 'O\s*=\s*\K[^/,]+' | head -1 || echo "$issuer")
            L "      $(t tls_issuer):  ${DIM}${issuer_short}${NC}"
        fi
        if [[ -n "$tls_version" ]]; then
            if [[ "$tls_version" == "TLSv1.3" ]]; then
                L "      TLS:     ${GREEN}${tls_version}${NC}"
            elif [[ "$tls_version" == "TLSv1.2" ]]; then
                L "      TLS:     ${GREEN}${tls_version}${NC}"
            elif [[ "$tls_version" == "TLSv1.1" ]] || [[ "$tls_version" == "TLSv1" ]]; then
                L "      TLS:     ${RED}${tls_version}${NC} — $(t tls_obsolete)"
            else
                L "      TLS:     ${YELLOW}${tls_version}${NC}"
            fi
        fi

        if [[ -n "$not_after" ]]; then
            local expiry_epoch now_epoch days_left
            expiry_epoch=$(date -d "$not_after" +%s 2>/dev/null || date -jf "%b %d %T %Y %Z" "$not_after" +%s 2>/dev/null || echo "0")
            now_epoch=$(date +%s)

            if [[ "$expiry_epoch" -gt 0 ]]; then
                days_left=$(( (expiry_epoch - now_epoch) / 86400 ))
                if [[ $days_left -lt 0 ]]; then
                    L "      ${FAIL} ${RED}$(t tls_expired "$(( days_left * -1 ))")${NC}"
                elif [[ $days_left -lt 14 ]]; then
                    L "      ${WARN} ${RED}$(t tls_expires_urgent "$days_left")${NC}"
                elif [[ $days_left -lt 30 ]]; then
                    L "      ${WARN} ${YELLOW}$(t tls_expires_soon "$days_left")${NC}"
                else
                    L "      ${OK} ${GREEN}$(t tls_valid "$days_left" "$not_after")${NC}"
                    certs_ok=$((certs_ok + 1))
                fi
            else
                L "      ${DIM}Expira: ${not_after}${NC}"
                certs_ok=$((certs_ok + 1))
            fi
        fi

        local hostname_ok=false
        if [[ -n "$sans" ]]; then
            for san in $sans; do
                if [[ "$mx_server" == "$san" ]]; then
                    hostname_ok=true
                    break
                fi
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
            L "      ${OK} $(t tls_hostname_ok)"
        else
            local cn
            cn=$(echo "$subject" | grep -oP 'CN\s*=\s*\K[^/,]+' | head -1 || true)
            if [[ "$mx_server" == "$cn" ]] || [[ "$cn" == \*.* && "${mx_server#*.}" == "${cn#\*.}" ]]; then
                L "      ${OK} $(t tls_hostname_cn_ok)"
            else
                L "      ${WARN} ${YELLOW}$(t tls_hostname_mismatch)${NC}"
                L "      ${DIM}SANs: ${sans:-none}${NC}"
            fi
        fi

        local subject_hash issuer_hash
        subject_hash=$(echo "$cert_info" | openssl x509 -noout -subject_hash 2>/dev/null || true)
        issuer_hash=$(echo "$cert_info" | openssl x509 -noout -issuer_hash 2>/dev/null || true)
        if [[ -n "$subject_hash" ]] && [[ "$subject_hash" == "$issuer_hash" ]]; then
            L "      ${FAIL} ${RED}$(t tls_self_signed)${NC}"
        fi

        LV
    done

    if [[ $certs_total -gt 0 ]]; then
        L " $(t tls_summary)"
        L "   ${INFO} ${certs_ok}/${certs_total} $(t tls_certs_valid)"
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
# 10. Subdomain protection
# ═════════════════════════════════════════════════════════════════════
auditar_subdominios() {
    local dominio="$1"
    seccion_inicio
    L "${BOLD}$(t sub_title)${NC}"
    L "${DIM}$(t sub_desc1)${NC}"
    L "${DIM}$(t sub_desc2)${NC}"
    L "${DIM}$(t sub_desc3)${NC}"
    L "${DIM}$(t sub_desc4)${NC}"
    LV

    local subdominios=("mail" "smtp" "email" "correo" "webmail"
                       "newsletter" "noreply" "no-reply" "bounce"
                       "marketing" "info" "soporte" "support"
                       "admin" "postmaster" "autoresponder")

    local protegidos=0
    local vulnerables=0
    local total_comprobados=0

    L "   ${DIM}$(printf '%-20s %-12s %s' "$(t sub_subdomain)" "SPF" "$(t sub_status)")${NC}"
    L "   ${DIM}$(printf '%-20s %-12s %s' "──────────────────" "──────────" "──────────────")${NC}"

    for sub in "${subdominios[@]}"; do
        local fqdn="${sub}.${dominio}"

        local tiene_dns
        tiene_dns=$(safe_dig +short A "$fqdn" || true)
        local tiene_mx_sub
        tiene_mx_sub=$(safe_dig +short MX "$fqdn" || true)

        if [[ -z "$tiene_dns" ]] && [[ -z "$tiene_mx_sub" ]]; then
            continue
        fi

        total_comprobados=$((total_comprobados + 1))

        local spf_sub
        spf_sub=$(safe_dig +short TXT "$fqdn" | grep -i "v=spf1" | tr -d '"' || true)

        if [[ -z "$spf_sub" ]]; then
            L "   ${YELLOW}$(printf '%-20s' "$sub")${NC} ${DIM}$(printf '%-12s' "(sin SPF)")${NC} ${WARN} $(t sub_vulnerable)"
            vulnerables=$((vulnerables + 1))
        elif echo "$spf_sub" | grep -q "\-all" && ! echo "$spf_sub" | grep -qi "include:\|a:\|mx:\|ip4:\|ip6:"; then
            L "   ${GREEN}$(printf '%-20s' "$sub")${NC} ${DIM}$(printf '%-12s' "null SPF")${NC} ${OK} $(t sub_protected)"
            protegidos=$((protegidos + 1))
        elif echo "$spf_sub" | grep -q "\-all"; then
            L "   ${GREEN}$(printf '%-20s' "$sub")${NC} ${DIM}$(printf '%-12s' "-all")${NC} ${OK} $(t sub_restrictive)"
            protegidos=$((protegidos + 1))
        elif echo "$spf_sub" | grep -q "\~all"; then
            L "   ${YELLOW}$(printf '%-20s' "$sub")${NC} ${DIM}$(printf '%-12s' "~all")${NC} ${WARN} $(t sub_softfail)"
            vulnerables=$((vulnerables + 1))
        else
            L "   ${YELLOW}$(printf '%-20s' "$sub")${NC} ${DIM}$(printf '%-12s' "otro")${NC} ${INFO} $(t sub_review)"
        fi
    done

    LV

    if [[ $total_comprobados -eq 0 ]]; then
        L " ${INFO} $(t sub_none_found)"
        L "   ${DIM}→ $(t sub_none_normal)${NC}"
        sumar_puntos 1 1
    elif [[ $vulnerables -eq 0 ]]; then
        L " ${OK} ${GREEN}$(t sub_all_protected "$protegidos" "$total_comprobados")${NC}"
        sumar_puntos 1 1
    else
        L " ${WARN} ${YELLOW}$(t sub_unprotected "$vulnerables")${NC}"
        L "   ${YELLOW}→ $(t sub_add_record)${NC}"
        sumar_puntos 0 1
    fi

    local dmarc_sp
    dmarc_sp=$(safe_dig +noall +answer TXT "_dmarc.${dominio}" | grep -oP 'sp=\K[^;]+' | tr -d '"' | head -1 || true)
    if [[ -n "$dmarc_sp" ]]; then
        LV
        L " ${INFO} $(t sub_dmarc_sp "$dmarc_sp")"
        if [[ "$dmarc_sp" == "reject" ]]; then
            L "   ${OK} ${GREEN}$(t sub_inherit_reject)${NC}"
        elif [[ "$dmarc_sp" == "quarantine" ]]; then
            L "   ${WARN} ${YELLOW}$(t sub_inherit_quarantine)${NC}"
        else
            L "   ${WARN} ${YELLOW}$(t sub_inherit_other "$dmarc_sp")${NC}"
        fi
    fi
    seccion_fin
}

# ─── No-mail warning ─────────────────────────────────────────────────
mostrar_aviso_sin_correo() {
    local dominio="$1"
    printf "\n"
    printf "${YELLOW}╔══════════════════════════════════════════════════════════════╗${NC}\n"
    printf "${YELLOW}║${NC}                                                              ${YELLOW}║${NC}\n"
    printf "${YELLOW}║${NC}  ${WARN} ${BOLD}$(t nomail_title)${NC} ${YELLOW}║${NC}\n"
    printf "${YELLOW}║${NC}                                                              ${YELLOW}║${NC}\n"
    printf "${YELLOW}║${NC}  $(t nomail_no_mx) ${CYAN}${dominio}${NC}               ${YELLOW}║${NC}\n"
    printf "${YELLOW}║${NC}                                                              ${YELLOW}║${NC}\n"
    printf "${YELLOW}║${NC}  $(t nomail_causes)                                            ${YELLOW}║${NC}\n"
    printf "${YELLOW}║${NC}    • $(t nomail_cause1)                             ${YELLOW}║${NC}\n"
    printf "${YELLOW}║${NC}    • $(t nomail_cause2)                     ${YELLOW}║${NC}\n"
    printf "${YELLOW}║${NC}    • $(t nomail_cause3)                 ${YELLOW}║${NC}\n"
    printf "${YELLOW}║${NC}                                                              ${YELLOW}║${NC}\n"
    printf "${YELLOW}╚══════════════════════════════════════════════════════════════╝${NC}\n"
    printf "\n"
    printf "$(t continue_anyway)"
    local respuesta
    read -r respuesta
    case "$respuesta" in
        [sS]|[sS][iI]|[yY]|[yY][eE][sS])
            return 0
            ;;
        *)
            printf "\n$(t audit_cancelled)\n"
            exit 0
            ;;
    esac
}

# ─── Summary ──────────────────────────────────────────────────────────
mostrar_resumen() {
    local dominio="$1"

    local porcentaje=0
    if [[ $MAX_SCORE -gt 0 ]]; then
        porcentaje=$((SCORE * 100 / MAX_SCORE))
    fi

    local nivel color emoji
    if [[ $porcentaje -ge 80 ]]; then
        nivel="$(t summary_good)"
        color="$GREEN"
        emoji="🟢"
    elif [[ $porcentaje -ge 50 ]]; then
        nivel="$(t summary_improvable)"
        color="$YELLOW"
        emoji="🟡"
    else
        nivel="$(t summary_poor)"
        color="$RED"
        emoji="🔴"
    fi

    local barra=""
    local llenos=$((porcentaje / 5))
    local vacios=$((20 - llenos))
    for ((i=0; i<llenos; i++)); do barra+="█"; done
    for ((i=0; i<vacios; i++)); do barra+="░"; done

    local recomendaciones=()

    local spf_check dmarc_check dnssec_present mta_sts_check tlsrpt_check bimi_check
    spf_check=$(safe_dig +short TXT "$dominio" | grep -i "v=spf1" || true)
    dmarc_check=$(safe_dig +noall +answer TXT "_dmarc.${dominio}" | grep -oP '"v=DMARC1[^"]*"' | head -1 || true)
    dnssec_present=$(safe_dig +short DNSKEY "$dominio" || true)
    mta_sts_check=$(safe_dig +short TXT "_mta-sts.${dominio}" | grep -i "STSv1" || true)
    tlsrpt_check=$(safe_dig +short TXT "_smtp._tls.${dominio}" | grep -i "TLSRPTv1" || true)
    bimi_check=$(safe_dig +short TXT "default._bimi.${dominio}" | grep -i "BIMI1" || true)

    if [[ -z "$spf_check" ]]; then
        recomendaciones+=("$(t rec_create_spf)")
    elif ! echo "$spf_check" | grep -q "\-all"; then
        if ! echo "$spf_check" | grep -q "redirect="; then
            recomendaciones+=("$(t rec_harden_spf)")
        fi
    fi

    if [[ -z "$dmarc_check" ]]; then
        recomendaciones+=("$(t rec_implement_dmarc)")
    elif echo "$dmarc_check" | grep -qP 'p=none' 2>/dev/null; then
        recomendaciones+=("$(t rec_dmarc_none_up)")
    elif echo "$dmarc_check" | grep -qP 'p=quarantine' 2>/dev/null; then
        recomendaciones+=("$(t rec_dmarc_quar_up)")
    fi

    if [[ -z "$dnssec_present" ]]; then
        recomendaciones+=("$(t rec_enable_dnssec)")
        recomendaciones+=("$(t rec_implement_dane)")
    fi

    if [[ -z "$mta_sts_check" ]]; then
        recomendaciones+=("$(t rec_implement_mtasts)")
    fi

    if [[ -z "$tlsrpt_check" ]]; then
        recomendaciones+=("$(t rec_add_tlsrpt)")
    fi

    if [[ -z "$bimi_check" ]]; then
        local dmarc_pol
        dmarc_pol=$(echo "$dmarc_check" | grep -oP 'p=\K[^;]+' | tr -d '"' | head -1 || true)
        if [[ "$dmarc_pol" == "reject" ]] || [[ "$dmarc_pol" == "quarantine" ]]; then
            recomendaciones+=("$(t rec_consider_bimi)")
        fi
    fi

    if [[ "$TIENE_MX" == false ]]; then
        recomendaciones+=("$(t rec_configure_mx)")
    fi

    printf "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}\n"
    linea_vacia
    linea_recuadro "${BOLD}                    $(t summary_title)${NC}"
    linea_vacia
    printf "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}\n"
    linea_vacia
    linea_recuadro "   ${color}[${barra}]${NC}  ${SCORE}/${MAX_SCORE} $(t summary_points) (${porcentaje}%)"
    linea_vacia
    local visible_nivel
    visible_nivel=$(printf '%b' "   $(t summary_level): ${nivel}  ${emoji}" | sed 's/\x1b\[[0-9;]*m//g')
    local len_nivel=${#visible_nivel}
    len_nivel=$((len_nivel + 1))
    local pad_nivel=$((W - len_nivel))
    if [[ $pad_nivel -lt 0 ]]; then pad_nivel=0; fi
    printf "${CYAN}║${NC}   $(t summary_level): ${color}${BOLD}${nivel}${NC}  ${emoji}%*s${CYAN}║${NC}\n" "$pad_nivel" ""
    linea_vacia

    printf "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}\n"
    linea_recuadro " ${BOLD}$(t summary_checks)${NC}"
    linea_vacia

    local check_mx check_spf check_dkim check_dmarc check_dane check_sts check_tlsrpt check_bimi
    [[ "$TIENE_MX" == true ]] && check_mx="${OK}" || check_mx="${FAIL}"
    [[ -n "$spf_check" ]] && check_spf="${OK}" || check_spf="${FAIL}"
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
    linea_recuadro " ${BOLD}$(t summary_recommendations)${NC}"
    linea_vacia

    if [[ ${#recomendaciones[@]} -eq 0 ]]; then
        linea_recuadro "  ${GREEN}✓ $(t summary_excellent)${NC}"
    else
        local i=1
        for rec in "${recomendaciones[@]}"; do
            linea_recuadro "  ${YELLOW}${i}. ${rec}${NC}"
            i=$((i + 1))
        done
    fi

    linea_vacia

    if [[ "$TIENE_OPENSSL" != true ]] || [[ "$TIENE_CURL" != true ]]; then
        printf "${CYAN}╠══════════════════════════════════════════════════════════════╣${NC}\n"
        linea_recuadro " ${BOLD}$(t summary_improve)${NC}"
        linea_vacia
        if [[ "$TIENE_OPENSSL" != true ]]; then
            linea_recuadro "  ${INFO} $(t summary_install_openssl)"
        fi
        if [[ "$TIENE_CURL" != true ]]; then
            linea_recuadro "  ${INFO} $(t summary_install_curl)"
        fi
        linea_vacia
    fi

    printf "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}\n"
    printf "\n"
}

# ─── Usage ────────────────────────────────────────────────────────────
mostrar_uso() {
    cat <<EOF
Usage: $0 [--lang es|en] [domain]

Options:
  --lang es   Force Spanish output
  --lang en   Force English output
  -h, --help  Show this help

If no --lang is given, the language is auto-detected from the system
locale (Spanish locales → ES, everything else → EN).
If no domain is given, it will be requested interactively.
EOF
    exit 0
}

# ─── Main ─────────────────────────────────────────────────────────────
main() {
    local dominio=""

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --lang|-l)
                shift
                case "${1:-}" in
                    es|ES) LANG_CODE="es" ;;
                    en|EN) LANG_CODE="en" ;;
                    *)
                        printf "Invalid language: '%s'. Use 'es' or 'en'.\n" "${1:-}"
                        exit 1
                        ;;
                esac
                shift
                ;;
            -h|--help)
                mostrar_uso
                ;;
            -*)
                printf "Unknown option: %s\n" "$1"
                mostrar_uso
                ;;
            *)
                dominio="$1"
                shift
                ;;
        esac
    done

    # Load translation strings
    if [[ "$LANG_CODE" == "es" ]]; then
        load_strings_es
    else
        load_strings_en
    fi

    comprobar_dependencias

    if [[ -z "$dominio" ]]; then
        printf "$(t enter_domain)"
        read -r dominio
    fi

    dominio=$(echo "$dominio" | sed -E 's|^https?://||; s|/.*||; s|^www\.||')

    validar_dominio "$dominio"
    verificar_dominio_existe "$dominio"
    mostrar_banner "$dominio"

    auditar_mx "$dominio"

    if [[ "$TIENE_MX" == false ]]; then
        mostrar_aviso_sin_correo "$dominio"
    fi

    auditar_spf "$dominio"
    auditar_dkim "$dominio"
    auditar_dmarc "$dominio"
    auditar_dane "$dominio"
    auditar_mta_sts "$dominio"
    auditar_tls_rpt "$dominio"
    auditar_bimi "$dominio"
    auditar_tls_certs "$dominio"
    auditar_subdominios "$dominio"

    mostrar_resumen "$dominio"
}

main "$@"
