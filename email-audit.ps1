#Requires -Version 5.1
<#
.SYNOPSIS
    email-audit.ps1 — Auditoría de autenticación de correo electrónico (Windows)
.DESCRIPTION
    Verifica SPF, DKIM, DMARC, MX y DANE/TLSA de un dominio.
    Equivalente funcional del script bash email-audit.sh.
.PARAMETER Dominio
    El dominio a auditar. Si no se pasa, se solicita de forma interactiva.
.EXAMPLE
    .\email-audit.ps1 ejemplo.com
    .\email-audit.ps1
#>

param(
    [Parameter(Position = 0)]
    [string]$Dominio
)

# ─── Configuración de consola ────────────────────────────────────────
$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# ─── Variables globales ──────────────────────────────────────────────
$script:Score = 0
$script:MaxScore = 0
$script:MxServers = @()
$script:TieneMx = $false
$script:W = 62  # ancho interno recuadro

# ─── Helper: repetir carácter (compatible PS 5.1) ────────────────────
function Rep {
    param([string]$Char, [int]$Count)
    if ($Count -le 0) { return '' }
    return ($Char * $Count)
}

# ─── Helper: emoji surrogate pair (compatible PS 5.1) ────────────────
function Emoji {
    param([int]$CodePoint)
    return [char]::ConvertFromUtf32($CodePoint)
}

# ─── Colores y símbolos ─────────────────────────────────────────────
$script:SupportsAnsi = ($PSVersionTable.PSVersion.Major -ge 7) -or ($env:WT_SESSION) -or ($env:ConEmuPID)

function C {
    param([string]$Color, [string]$Text)
    if ($script:SupportsAnsi) {
        $codes = @{
            'Bold' = "`e[1m"; 'Dim' = "`e[2m"
            'Red' = "`e[31m"; 'Green' = "`e[32m"
            'Yellow' = "`e[33m"; 'Blue' = "`e[34m"
            'Cyan' = "`e[36m"; 'NC' = "`e[0m"
        }
        return "$($codes[$Color])$Text$($codes['NC'])"
    }
    return $Text
}

function Write-C {
    param([string]$Color, [string]$Text, [switch]$NoNewline)
    if ($script:SupportsAnsi) {
        $str = C $Color $Text
        if ($NoNewline) { Write-Host $str -NoNewline } else { Write-Host $str }
    }
    else {
        $colorMap = @{
            'Bold' = 'White'; 'Dim' = 'DarkGray'; 'Red' = 'Red'; 'Green' = 'Green'
            'Yellow' = 'Yellow'; 'Blue' = 'Blue'; 'Cyan' = 'Cyan'; 'NC' = 'Gray'
        }
        $fc = if ($colorMap.ContainsKey($Color)) { $colorMap[$Color] } else { 'Gray' }
        if ($NoNewline) { Write-Host $Text -ForegroundColor $fc -NoNewline } else { Write-Host $Text -ForegroundColor $fc }
    }
}

$script:OK = "$(C 'Green' ([char]0x2713))"
$script:WARN = "$(C 'Yellow' ([char]0x26A0))"
$script:FAIL = "$(C 'Red' ([char]0x2717))"
$script:INFO = "$(C 'Cyan' ([char]0x2139))"

function Sumar-Puntos { param([int]$Pts, [int]$Max); $script:Score += $Pts; $script:MaxScore += $Max }

# ─── Caracteres de recuadro (como string, no char) ──────────────────
$script:BOX_H = [string][char]0x2500  # ─
$script:BOX_DH = [string][char]0x2550  # ═
$script:BOX_V = [string][char]0x2502  # │
$script:BOX_DV = [string][char]0x2551  # ║
$script:BOX_TL = [string][char]0x250C  # ┌
$script:BOX_TR = [string][char]0x2510  # ┐
$script:BOX_BL = [string][char]0x2514  # └
$script:BOX_BR = [string][char]0x2518  # ┘
$script:BOX_DTL = [string][char]0x2554 # ╔
$script:BOX_DTR = [string][char]0x2557 # ╗
$script:BOX_DBL = [string][char]0x255A # ╚
$script:BOX_DBR = [string][char]0x255D # ╝
$script:BOX_DML = [string][char]0x2560 # ╠
$script:BOX_DMR = [string][char]0x2563 # ╣

# ─── Utilidades de recuadro ──────────────────────────────────────────
function Strip-Ansi {
    param([string]$Text)
    return [regex]::Replace($Text, '\x1b\[[0-9;]*m', '')
}

function Linea-Recuadro {
    param([string]$Texto)
    $visible = Strip-Ansi $Texto
    $pad = $script:W - $visible.Length
    if ($pad -lt 0) { $pad = 0 }
    Write-Host "$(C 'Cyan' $script:BOX_DV)$Texto$(Rep ' ' $pad)$(C 'Cyan' $script:BOX_DV)"
}

function Linea-Vacia {
    Write-Host "$(C 'Cyan' $script:BOX_DV)$(Rep ' ' $script:W)$(C 'Cyan' $script:BOX_DV)"
}

function L {
    param([string]$Texto = '')
    Write-Host "$(C 'Blue' $script:BOX_V) $Texto"
}

function LV { Write-Host "$(C 'Blue' $script:BOX_V)" }

function Seccion-Inicio {
    Write-Host "$(C 'Blue' $script:BOX_TL)$(Rep $script:BOX_H 62)$(C 'Blue' $script:BOX_TR)"
}

function Seccion-Fin {
    Write-Host "$(C 'Blue' $script:BOX_BL)$(Rep $script:BOX_H 62)$(C 'Blue' $script:BOX_BR)"
    Write-Host ""
}

# ─── DNS helper ──────────────────────────────────────────────────────
function Safe-DnsResolve {
    param(
        [string]$Name,
        [string]$Type = 'A',
        [string]$Server = ''
    )
    try {
        $params = @{ Name = $Name; Type = $Type; ErrorAction = 'Stop'; DnsOnly = $true }
        if ($Server) { $params['Server'] = $Server }
        return (Resolve-DnsName @params)
    }
    catch {
        return $null
    }
}

# ─── Comprobación de dependencias ────────────────────────────────────
function Comprobar-Dependencias {
    if (-not (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue)) {
        Write-C 'Red' "Error: Resolve-DnsName no esta disponible."
        Write-C 'Yellow' "Se requiere Windows 8+ o Windows Server 2012+ con el modulo DnsClient."
        exit 1
    }
}

# ─── Validar dominio ─────────────────────────────────────────────────
function Validar-Dominio {
    param([string]$Dom)
    if ($Dom -notmatch '^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)+$') {
        Write-C 'Red' "Error: '$Dom' no parece un dominio valido."
        exit 1
    }
}

# ─── Verificar existencia DNS ────────────────────────────────────────
function Verificar-DominioExiste {
    param([string]$Dom)
    $a = Safe-DnsResolve -Name $Dom -Type 'A'
    $ns = Safe-DnsResolve -Name $Dom -Type 'NS'
    if (-not $a -and -not $ns) {
        Write-Host ""
        Write-C 'Red' (Rep '=' 62)
        Write-C 'Red' "  $([char]0x2717) El dominio '$Dom' no tiene registros DNS."
        Write-C 'Red' "  Esta bien escrito? Comprueba que no haya erratas."
        Write-C 'Red' (Rep '=' 62)
        Write-Host ""
        exit 1
    }
}

# ─── Banner ──────────────────────────────────────────────────────────
function Mostrar-Banner {
    param([string]$Dom)
    $fecha = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host ""
    Write-Host "$(C 'Cyan' $script:BOX_DTL)$(Rep $script:BOX_DH 62)$(C 'Cyan' $script:BOX_DTR)"
    Linea-Vacia
    Linea-Recuadro "$(C 'Bold' '      AUDITORIA DE AUTENTICACION DE CORREO ELECTRONICO')"
    Linea-Vacia
    Write-Host "$(C 'Cyan' $script:BOX_DML)$(Rep $script:BOX_DH 62)$(C 'Cyan' $script:BOX_DMR)"
    Linea-Recuadro "  Dominio:  $Dom"
    Linea-Recuadro "  Fecha:    $fecha"
    Linea-Recuadro "  Checks:   SPF - DKIM - DMARC - MX - DANE/TLSA"
    Write-Host "$(C 'Cyan' $script:BOX_DBL)$(Rep $script:BOX_DH 62)$(C 'Cyan' $script:BOX_DBR)"
    Write-Host ""
}

# ─── MX ──────────────────────────────────────────────────────────────
function Auditar-MX {
    param([string]$Dom)
    Seccion-Inicio
    L "$(C 'Bold' '1. MX (Mail eXchange)')"
    L "$(C 'Dim' 'Servidores responsables de recibir correo para el dominio')"
    LV

    $mx = Safe-DnsResolve -Name $Dom -Type 'MX'

    if (-not $mx -or ($mx | Where-Object { $_.QueryType -eq 'MX' }).Count -eq 0) {
        L " $($script:FAIL) No se encontraron registros MX"
        L "   $(C 'Yellow' '-> Este dominio no puede recibir correo')"
        Sumar-Puntos 0 2
        $script:TieneMx = $false
        Seccion-Fin
        return
    }

    $script:TieneMx = $true
    $mxRecords = $mx | Where-Object { $_.QueryType -eq 'MX' } | Sort-Object Preference

    L " $($script:OK) Servidores MX encontrados:"
    LV
    L "   $(C 'Dim' ('{0,-12} {1,-45}' -f 'PRIORIDAD', 'SERVIDOR'))"
    L "   $(C 'Dim' ('{0,-12} {1,-45}' -f (Rep $script:BOX_H 9), (Rep $script:BOX_H 32)))"

    $script:MxServers = @()

    foreach ($r in $mxRecords) {
        $pref = $r.Preference
        $srv = $r.NameExchange.ToString().TrimEnd('.')
        L "   $(C 'Cyan' ('{0,-12}' -f $pref)) $(C 'Cyan' $srv)"
        $script:MxServers += $srv
    }

    Sumar-Puntos 2 2
    LV

    # Detección de proveedor
    $mxJoined = ($mxRecords | ForEach-Object { $_.NameExchange }) -join ' '

    $proveedores = [ordered]@{
        # --- Proveedores principales ---
        'google|gmail|googlemail'              = 'Google Workspace'
        'outlook|microsoft'                    = 'Microsoft 365'
        'protonmail|proton'                    = 'ProtonMail'
        'zoho'                                 = 'Zoho Mail'
        'yahoo|yahoodns'                       = 'Yahoo Mail'
        'icloud|apple|me\.com'                 = 'Apple iCloud Mail'
        'yandex'                               = 'Yandex Mail'
        'fastmail'                             = 'Fastmail'
        'tutanota|tuta\.io'                    = 'Tuta (Tutanota)'
        'mailfence'                            = 'Mailfence'
        'migadu'                               = 'Migadu'

        # --- Gateways de seguridad ---
        'mimecast'                             = 'Mimecast'
        'barracuda'                            = 'Barracuda'
        'pphosted|proofpoint'                  = 'Proofpoint'
        'messagelabs|symantec\.email|broadcom' = 'Symantec/Broadcom Email Security'
        'trendmicro|in\.hes\.trendmicro'       = 'Trend Micro Email Security'
        'sophos|reflexion'                     = 'Sophos Email'
        'forcepoint|mailcontrol'               = 'Forcepoint'
        'cisco|ironport|iphmx'                 = 'Cisco Secure Email (IronPort)'
        'fireeye|trellix'                      = 'Trellix (FireEye) Email Security'
        'spamexperts|antispamcloud'            = 'SpamExperts'
        'hornetsecurity|hornetdrive'           = 'Hornetsecurity'
        'cloudflare'                           = 'Cloudflare Email Routing'

        # --- Envío transaccional / marketing ---
        'mailgun'                              = 'Mailgun'
        'sendgrid'                             = 'SendGrid (Twilio)'
        'amazonses|amazonaws'                  = 'Amazon SES'
        'postmarkapp'                          = 'Postmark'
        'mailchimp|mandrillapp'                = 'Mailchimp / Mandrill'
        'mailjet'                              = 'Mailjet'

        # --- Hosting / registradores ---
        'ovh'                                  = 'OVH'
        'ionos|1and1|perfora|kundenserver'     = 'IONOS (1&1)'
        'gandi'                                = 'Gandi'
        'hover'                                = 'Hover'
        'namecheap|privateemail'               = 'Namecheap (Private Email)'
        'godaddy|secureserver'                 = 'GoDaddy'
        'rackspace|emailsrvr'                  = 'Rackspace Email'
        'hostgator|websitewelcome'             = 'HostGator'
        'bluehost'                             = 'Bluehost'
        'dreamhost'                            = 'DreamHost'
        'hetzner'                              = 'Hetzner'
        'strato'                               = 'Strato'
        'arsys|nicline'                        = 'Arsys'
        'dinahosting'                          = 'Dinahosting'

        # --- Paneles de control ---
        'cpanel|whm'                           = 'cPanel Mail'
        'plesk'                                = 'Plesk Mail'
        'zimbra'                               = 'Zimbra'
    }

    $detected = $false
    Write-Host "$(C 'Blue' $script:BOX_V)  Proveedor detectado: " -NoNewline
    foreach ($pattern in $proveedores.Keys) {
        if ($mxJoined -match $pattern) {
            Write-C 'Green' $proveedores[$pattern]
            $detected = $true
            break
        }
    }
    if (-not $detected) {
        $firstMx = $mxRecords[0].NameExchange.ToString().TrimEnd('.')
        Write-Host "$(C 'Yellow' 'No identificado') ($(C 'Dim' $firstMx))"
    }

    Seccion-Fin
}

# ─── SPF ─────────────────────────────────────────────────────────────
function Auditar-SPF {
    param([string]$Dom)
    Seccion-Inicio
    L "$(C 'Bold' '2. SPF (Sender Policy Framework)')"
    L "$(C 'Dim' 'Define que servidores pueden enviar correo por este dominio')"
    LV

    $txtRecords = Safe-DnsResolve -Name $Dom -Type 'TXT'
    $spf = $null
    if ($txtRecords) {
        $spf = $txtRecords | Where-Object { $_.Strings -match 'v=spf1' } | Select-Object -First 1
    }

    if (-not $spf) {
        L " $($script:FAIL) No se encontro registro SPF"
        L "   $(C 'Yellow' '-> Vulnerable a spoofing')"
        Sumar-Puntos 0 3
        Seccion-Fin
        return
    }

    $spfText = ($spf.Strings) -join ''
    L " $($script:OK) Registro encontrado:"
    L "   $(C 'Cyan' $spfText)"
    LV

    # redirect=
    $redirect = [regex]::Match($spfText, 'redirect=([^\s]+)')
    if ($redirect.Success) {
        $rDom = $redirect.Groups[1].Value
        L " $($script:INFO) Usa $(C 'Cyan' "redirect=$rDom")"

        $rTxt = Safe-DnsResolve -Name $rDom -Type 'TXT'
        $rSpf = $null
        if ($rTxt) { $rSpf = $rTxt | Where-Object { $_.Strings -match 'v=spf1' } | Select-Object -First 1 }

        if ($rSpf) {
            $rSpfText = ($rSpf.Strings) -join ''
            $display = if ($rSpfText.Length -gt 70) { $rSpfText.Substring(0, 67) + '...' } else { $rSpfText }
            L "   SPF delegado: $(C 'Dim' $display)"

            if ($rSpfText -match '-all') {
                L " $($script:OK) Politica heredada: $(C 'Green' 'ESTRICTA (-all)')"
                Sumar-Puntos 3 3
            }
            elseif ($rSpfText -match '~all') {
                L " $($script:WARN) Politica heredada: $(C 'Yellow' 'SUAVE (~all)')"
                Sumar-Puntos 2 3
            }
            else {
                L " $($script:WARN) Politica heredada no determinada claramente"
                Sumar-Puntos 1 3
            }
        }
        else {
            L " $($script:WARN) No se pudo resolver el SPF del dominio redirect"
            Sumar-Puntos 1 3
        }
    }
    elseif ($spfText -match '-all') {
        L " $($script:OK) Politica: $(C 'Green' 'ESTRICTA (-all)') - rechaza correo no autorizado"
        Sumar-Puntos 3 3
    }
    elseif ($spfText -match '~all') {
        L " $($script:WARN) Politica: $(C 'Yellow' 'SUAVE (~all)') - marca como sospechoso, no rechaza"
        Sumar-Puntos 2 3
    }
    elseif ($spfText -match '\?all') {
        L " $($script:WARN) Politica: $(C 'Yellow' 'NEUTRAL (?all)') - sin accion"
        Sumar-Puntos 1 3
    }
    elseif ($spfText -match '\+all') {
        L " $($script:FAIL) Politica: $(C 'Red' 'ABIERTA (+all)') - cualquiera puede suplantar!"
        Sumar-Puntos 0 3
    }
    else {
        L " $($script:WARN) No se detecto mecanismo 'all' explicito"
        Sumar-Puntos 1 3
    }

    $lookups = ([regex]::Matches($spfText, '(include:|a:|mx:|ptr:|redirect=)')).Count
    if ($lookups -gt 10) {
        L " $($script:FAIL) DNS lookups: $(C 'Red' "$lookups/10") - excede RFC 7208"
    }
    elseif ($lookups -gt 7) {
        L " $($script:WARN) DNS lookups: $(C 'Yellow' "$lookups/10") - cerca del limite"
    }
    else {
        L " $($script:OK) DNS lookups: $(C 'Green' "$lookups/10")"
    }
    Seccion-Fin
}

# ─── DKIM ────────────────────────────────────────────────────────────
function Auditar-DKIM {
    param([string]$Dom)
    Seccion-Inicio
    L "$(C 'Bold' '3. DKIM (DomainKeys Identified Mail)')"
    L "$(C 'Dim' 'Firma criptografica que verifica la integridad del mensaje')"
    LV

    $selectores = @(
        'default', 'google', 'selector1', 'selector2', 'k1', 'k2',
        'mail', 'dkim', 's1', 's2', 'smtp', 'mandrill', 'everlytickey1',
        'mxvault', 'cm', 'protonmail', 'protonmail2', 'protonmail3',
        '20230601', '20221208', '20210112', '20161025',
        'sig1', 'm1', 'smtp2', 'email', 'mkto', 'aweber', 'constantcontact',
        'zohocorp', 'zendesk1', 'zendesk2', 'ovh', 'mailjet', 'mg', 'krs', 'mailo',
        'pic', 'intercom', 'hs1', 'hs2', 'dk', 'kl', 'neolane', 'mta', 'mindbox',
        'sailthru', 'qualtrics', 'fnc', 'firebase1'
    )

    $encontrados = 0
    foreach ($sel in $selectores) {
        $dkimName = "$sel._domainkey.$Dom"
        $result = Safe-DnsResolve -Name $dkimName -Type 'TXT'
        if ($result) {
            $joined = ($result | ForEach-Object { $_.Strings -join '' }) -join ''
            if ($joined -match 'p=') {
                if ($encontrados -eq 0) {
                    L " $($script:OK) Registros DKIM encontrados:"
                }
                L "   Selector: $(C 'Cyan' ('{0,-15}' -f $sel)) -> $(C 'Green' 'Presente')"
                $encontrados++
            }
        }
    }

    if ($encontrados -eq 0) {
        L " $($script:WARN) Sin registros DKIM en selectores comunes"
        L "   $(C 'Yellow' '-> Puede usar un selector personalizado no probado')"
        L "   $(C 'Dim' "Prueba manual: Resolve-DnsName -Type TXT <selector>._domainkey.$Dom")"
        Sumar-Puntos 0 2
    }
    else {
        L " $($script:OK) Total: $(C 'Green' $encontrados) selector(es) DKIM verificados"
        Sumar-Puntos 2 2
    }
    Seccion-Fin
}

# ─── DMARC ───────────────────────────────────────────────────────────
function Auditar-DMARC {
    param([string]$Dom)
    Seccion-Inicio
    L "$(C 'Bold' '4. DMARC (Domain-based Message Authentication, Reporting & Conformance)')"
    L "$(C 'Dim' 'Politica que une SPF y DKIM e indica como tratar fallos')"
    LV

    $dmarcName = "_dmarc.$Dom"
    $dmarcResult = Safe-DnsResolve -Name $dmarcName -Type 'TXT'

    $dmarcRecord = $null
    if ($dmarcResult) {
        $dmarcRecord = $dmarcResult | Where-Object { ($_.Strings -join '') -match 'v=DMARC1' } | Select-Object -First 1
    }

    # Comprobar CNAME
    $cnameTarget = $null
    if ($dmarcResult) {
        $cname = $dmarcResult | Where-Object { $_.QueryType -eq 'CNAME' } | Select-Object -First 1
        if ($cname) { $cnameTarget = $cname.NameHost }
    }

    if (-not $dmarcRecord) {
        L " $($script:FAIL) No se encontro registro DMARC"
        L "   $(C 'Yellow' '-> Sin instrucciones para correo no autenticado')"
        Sumar-Puntos 0 3
        Seccion-Fin
        return
    }

    $dmarcText = ($dmarcRecord.Strings) -join ''

    L " $($script:OK) Registro encontrado:"
    if ($cnameTarget) {
        L "   $(C 'Dim' "(delegado via CNAME -> $cnameTarget)")"
    }
    L "   $(C 'Cyan' $dmarcText)"
    LV

    # Política
    $polMatch = [regex]::Match($dmarcText, 'p=([^;\s]+)')
    $politica = if ($polMatch.Success) { $polMatch.Groups[1].Value } else { '' }

    switch ($politica) {
        'reject' {
            L " $($script:OK) Politica: $(C 'Green' 'REJECT') - rechaza correo no autenticado"
            Sumar-Puntos 3 3
        }
        'quarantine' {
            L " $($script:WARN) Politica: $(C 'Yellow' 'QUARANTINE') - envia a spam"
            Sumar-Puntos 2 3
        }
        'none' {
            L " $($script:WARN) Politica: $(C 'Yellow' 'NONE') - solo monitoriza, sin proteccion activa"
            Sumar-Puntos 1 3
        }
        default {
            L " $($script:WARN) Politica no reconocida: '$politica'"
            Sumar-Puntos 0 3
        }
    }

    # Subdominio
    $spMatch = [regex]::Match($dmarcText, 'sp=([^;\s]+)')
    if ($spMatch.Success) {
        L "   Subdominios (sp): $(C 'Cyan' $spMatch.Groups[1].Value)"
    }

    # pct
    $pctMatch = [regex]::Match($dmarcText, 'pct=(\d+)')
    if ($pctMatch.Success) {
        $pctVal = [int]$pctMatch.Groups[1].Value
        if ($pctVal -lt 100) {
            L " $($script:WARN) Aplicado solo al $(C 'Yellow' "$pctVal%") del correo (objetivo: 100%)"
        }
    }

    # Reportes
    $ruaMatch = [regex]::Match($dmarcText, 'rua=([^;\s]+)')
    $rufMatch = [regex]::Match($dmarcText, 'ruf=([^;\s]+)')
    LV
    L " Reportes:"
    if ($ruaMatch.Success) {
        L "   $($script:OK) Agregados (rua): $(C 'Cyan' $ruaMatch.Groups[1].Value)"
    }
    else {
        L "   $($script:WARN) Sin reportes agregados (rua)"
    }
    if ($rufMatch.Success) {
        L "   $($script:OK) Forenses  (ruf): $(C 'Cyan' $rufMatch.Groups[1].Value)"
    }
    else {
        L "   $($script:INFO) Sin reportes forenses (ruf) - opcional"
    }
    Seccion-Fin
}

# ─── DANE / TLSA ─────────────────────────────────────────────────────
function Auditar-DANE {
    param([string]$Dom)
    Seccion-Inicio
    L "$(C 'Bold' '5. DANE/TLSA (DNS-based Authentication of Named Entities)')"
    L "$(C 'Dim' 'Vincula certificados TLS a registros DNS (requiere DNSSEC)')"
    LV

    # DNSSEC
    $dnssecOk = $false
    $dnskey = Safe-DnsResolve -Name $Dom -Type 'DNSKEY'

    if ($dnskey) {
        try {
            $adCheck = Resolve-DnsName -Name $Dom -Type A -DnssecOk -ErrorAction Stop
            if ($adCheck) {
                L " $($script:OK) DNSSEC: $(C 'Green' 'Validado (DNSKEY presente, consulta DNSSEC OK)')"
                $dnssecOk = $true
            }
        }
        catch {
            L " $($script:WARN) DNSSEC: $(C 'Yellow' 'DNSKEY encontrado, sin validacion completa')"
            L "   $(C 'Dim' 'Puede depender del resolver utilizado')"
            $dnssecOk = $true
        }
    }
    else {
        L " $($script:FAIL) DNSSEC: $(C 'Red' 'No habilitado')"
        L "   $(C 'Yellow' '-> DANE requiere DNSSEC para funcionar')"
    }

    LV

    if ($script:MxServers.Count -eq 0) {
        L " $($script:WARN) Sin servidores MX - no se puede verificar TLSA"
        Sumar-Puntos 0 2
        Seccion-Fin
        return
    }

    $tlsaEncontrados = 0
    $tlsaTotal = 0
    $starttlsCount = 0

    L " Registros TLSA (puerto 25/SMTP) por servidor MX:"
    LV

    $usageDesc = @{ 0 = 'CA constraint (PKIX-TA)'; 1 = 'Service cert (PKIX-EE)'; 2 = 'Trust anchor (DANE-TA)'; 3 = 'Domain cert (DANE-EE)' }
    $selectorDesc = @{ 0 = 'Cert completo'; 1 = 'Clave publica' }
    $matchDesc = @{ 0 = 'Exact'; 1 = 'SHA-256'; 2 = 'SHA-512' }

    foreach ($mxSrv in $script:MxServers) {
        $mxSrv = $mxSrv.TrimEnd('.')
        $tlsaTotal++

        # Resolve-DnsName no soporta TLSA en todas las versiones
        # Intentamos con tipo 52 (TLSA record type number)
        $tlsa = $null
        try {
            $tlsa = Resolve-DnsName -Name "_25._tcp.$mxSrv" -Type 52 -ErrorAction Stop -DnsOnly 2>$null
        }
        catch {}

        # Fallback: nslookup
        if (-not $tlsa) {
            try {
                $nslookupOutput = (nslookup -type=TLSA "_25._tcp.$mxSrv" 2>&1) | Out-String
                if ($nslookupOutput -match 'TLSA') {
                    L "   $($script:OK) $(C 'Cyan' $mxSrv)"
                    L "      $(C 'Dim' '(TLSA detectado via nslookup, detalles limitados)')"
                    $tlsaEncontrados++
                    continue
                }
            }
            catch {}
        }

        if ($tlsa) {
            $tlsaEncontrados++
            L "   $($script:OK) $(C 'Cyan' $mxSrv)"

            foreach ($rec in $tlsa) {
                if ($rec.PSObject.Properties.Name -contains 'CertificateUsage') {
                    $u = $rec.CertificateUsage
                    $s = $rec.Selector
                    $m = $rec.MatchingType
                    $uDesc = if ($usageDesc.ContainsKey([int]$u)) { $usageDesc[[int]$u] } else { 'Desconocido' }
                    $sDesc = if ($selectorDesc.ContainsKey([int]$s)) { $selectorDesc[[int]$s] } else { 'Desconocido' }
                    $mDesc = if ($matchDesc.ContainsKey([int]$m)) { $matchDesc[[int]$m] } else { 'Desconocido' }
                    L "      Uso: $(C 'Green' $u) ($uDesc)"
                    L "      Selector: $s ($sDesc) - Match: $m ($mDesc)"
                }
            }
        }
        else {
            L "   $($script:FAIL) $(C 'Cyan' $mxSrv) -> Sin TLSA"
        }

        # STARTTLS
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $connectTask = $tcp.ConnectAsync($mxSrv, 25)
            if ($connectTask.Wait(5000)) {
                $stream = $tcp.GetStream()
                $reader = New-Object System.IO.StreamReader($stream)
                $writer = New-Object System.IO.StreamWriter($stream)
                $writer.AutoFlush = $true

                $stream.ReadTimeout = 5000
                $banner = $reader.ReadLine()

                $writer.WriteLine("EHLO audit-test")
                Start-Sleep -Milliseconds 500

                $ehloResponse = ''
                while ($stream.DataAvailable) {
                    $ehloResponse += $reader.ReadLine() + "`n"
                }

                if ($ehloResponse -match 'STARTTLS') {
                    L "      $($script:OK) STARTTLS: $(C 'Green' 'Soportado')"
                    $starttlsCount++
                }
                elseif ($ehloResponse) {
                    L "      $($script:WARN) STARTTLS: $(C 'Yellow' 'No anunciado en EHLO')"
                }

                $writer.WriteLine("QUIT")
                $tcp.Close()
            }
            else {
                L "      $($script:INFO) STARTTLS: $(C 'Dim' 'Sin respuesta en puerto 25')"
                $tcp.Close()
            }
        }
        catch {
            L "      $($script:INFO) STARTTLS: $(C 'Dim' 'No se pudo conectar al puerto 25')"
        }
        LV
    }

    L " Resumen DANE/TLSA:"
    if ($tlsaEncontrados -gt 0 -and $dnssecOk) {
        L "   $($script:OK) $(C 'Green' "$tlsaEncontrados/$tlsaTotal") servidores MX con TLSA"
        if ($tlsaEncontrados -eq $tlsaTotal) { Sumar-Puntos 2 2 } else { Sumar-Puntos 1 2 }
    }
    elseif ($tlsaEncontrados -gt 0) {
        L "   $($script:WARN) TLSA encontrados pero $(C 'Yellow' 'DNSSEC no validado')"
        Sumar-Puntos 1 2
    }
    else {
        L "   $($script:FAIL) Sin registros TLSA en ningun servidor MX"
        if ($dnssecOk) {
            L "   $(C 'Yellow' '-> DNSSEC activo: buen momento para implementar DANE')"
        }
        else {
            L "   $(C 'Yellow' '-> Habilitar DNSSEC primero, luego anadir TLSA')"
        }
        Sumar-Puntos 0 2
    }

    if ($starttlsCount -gt 0) {
        L "   $($script:OK) STARTTLS verificado en $(C 'Green' $starttlsCount) servidor(es)"
    }
    Seccion-Fin
}

# ─── Aviso sin correo ────────────────────────────────────────────────
function Mostrar-AvisoSinCorreo {
    param([string]$Dom)
    Write-Host ""
    Write-C 'Yellow' (Rep '=' 62)
    Write-Host ""
    Write-Host "  $($script:WARN) $(C 'Bold' 'Este dominio no parece tener correo electronico configurado')"
    Write-Host ""
    Write-Host "  No se encontraron registros MX para $(C 'Cyan' $Dom)"
    Write-Host ""
    Write-Host "  Posibles causas:"
    Write-Host "    - Error al escribir el dominio"
    Write-Host "    - El dominio no usa correo electronico"
    Write-Host "    - Los registros MX aun no se han propagado"
    Write-Host ""
    Write-C 'Yellow' (Rep '=' 62)
    Write-Host ""

    $resp = Read-Host "Continuar igualmente con la auditoria? [s/N]"
    if ($resp -notmatch '^[sS]([iI])?$|^[yY]([eE][sS])?$') {
        Write-Host "`nAuditoria cancelada."
        exit 0
    }
}

# ─── Resumen ─────────────────────────────────────────────────────────
function Mostrar-Resumen {
    param([string]$Dom)

    $porcentaje = 0
    if ($script:MaxScore -gt 0) { $porcentaje = [math]::Floor($script:Score * 100 / $script:MaxScore) }

    # Emojis via surrogate pairs (compatible PS 5.1)
    if ($porcentaje -ge 80) {
        $nivel = 'BUENO'; $color = 'Green'; $emoji = Emoji 0x1F7E2  # verde
    }
    elseif ($porcentaje -ge 50) {
        $nivel = 'MEJORABLE'; $color = 'Yellow'; $emoji = Emoji 0x1F7E1  # amarillo
    }
    else {
        $nivel = 'DEFICIENTE'; $color = 'Red'; $emoji = Emoji 0x1F534  # rojo
    }

    $bloque = [string][char]0x2588  # █
    $sombra = [string][char]0x2591  # ░
    $llenos = [math]::Floor($porcentaje / 5)
    $vacios = 20 - $llenos
    $barra = (Rep $bloque $llenos) + (Rep $sombra $vacios)

    # Recomendaciones
    $recomendaciones = @()

    $spfCheck = Safe-DnsResolve -Name $Dom -Type 'TXT'
    $spfTxt = ''
    if ($spfCheck) {
        $spfRec = $spfCheck | Where-Object { $_.Strings -match 'v=spf1' } | Select-Object -First 1
        if ($spfRec) { $spfTxt = ($spfRec.Strings) -join '' }
    }

    $dmarcTxt = ''
    $dmarcCheck = Safe-DnsResolve -Name "_dmarc.$Dom" -Type 'TXT'
    if ($dmarcCheck) {
        $dmarcRec = $dmarcCheck | Where-Object { ($_.Strings -join '') -match 'v=DMARC1' } | Select-Object -First 1
        if ($dmarcRec) { $dmarcTxt = ($dmarcRec.Strings) -join '' }
    }

    $dnssecPresent = Safe-DnsResolve -Name $Dom -Type 'DNSKEY'

    if (-not $spfTxt) {
        $recomendaciones += 'Crear registro SPF con politica -all'
    }
    elseif ($spfTxt -notmatch '-all' -and $spfTxt -notmatch 'redirect=') {
        $recomendaciones += 'Endurecer SPF: migrar a -all'
    }

    if (-not $dmarcTxt) {
        $recomendaciones += 'Implementar DMARC (empezar con p=none + rua)'
    }
    elseif ($dmarcTxt -match 'p=none') {
        $recomendaciones += 'DMARC: evolucionar none -> quarantine -> reject'
    }
    elseif ($dmarcTxt -match 'p=quarantine') {
        $recomendaciones += 'DMARC: evolucionar quarantine -> reject'
    }

    if (-not $dnssecPresent) {
        $recomendaciones += 'Habilitar DNSSEC para proteger integridad DNS'
        $recomendaciones += 'Tras DNSSEC, implementar DANE/TLSA en MX'
    }

    if (-not $script:TieneMx) {
        $recomendaciones += 'Configurar registros MX para recibir correo'
    }

    # Recuadro
    Write-Host "$(C 'Cyan' $script:BOX_DTL)$(Rep $script:BOX_DH 62)$(C 'Cyan' $script:BOX_DTR)"
    Linea-Vacia
    Linea-Recuadro "$(C 'Bold' '                    RESULTADO FINAL')"
    Linea-Vacia
    Write-Host "$(C 'Cyan' $script:BOX_DML)$(Rep $script:BOX_DH 62)$(C 'Cyan' $script:BOX_DMR)"
    Linea-Vacia
    Linea-Recuadro "   $(C $color "[$barra]")  $($script:Score)/$($script:MaxScore) puntos ($porcentaje%)"
    Linea-Vacia
    Linea-Recuadro "   Nivel de seguridad: $(C $color $nivel)  $emoji"
    Linea-Vacia
    Write-Host "$(C 'Cyan' $script:BOX_DML)$(Rep $script:BOX_DH 62)$(C 'Cyan' $script:BOX_DMR)"
    Linea-Recuadro " $(C 'Bold' 'Recomendaciones:')"
    Linea-Vacia

    if ($recomendaciones.Count -eq 0) {
        Linea-Recuadro "  $(C 'Green' "$([char]0x2713) Configuracion excelente. Revisar periodicamente.")"
    }
    else {
        foreach ($rec in $recomendaciones) {
            Linea-Recuadro "  $(C 'Yellow' "-> $rec")"
        }
    }

    Linea-Vacia
    Write-Host "$(C 'Cyan' $script:BOX_DBL)$(Rep $script:BOX_DH 62)$(C 'Cyan' $script:BOX_DBR)"
    Write-Host ""
}

# ─── Main ────────────────────────────────────────────────────────────
function Main {
    Comprobar-Dependencias

    if (-not $Dominio) {
        $Dominio = Read-Host "Introduce el dominio a auditar"
    }

    # Limpiar entrada
    $Dominio = $Dominio -replace '^https?://', '' -replace '/.*', '' -replace '^www\.', ''

    Validar-Dominio $Dominio
    Verificar-DominioExiste $Dominio
    Mostrar-Banner $Dominio

    Auditar-MX $Dominio

    if (-not $script:TieneMx) {
        Mostrar-AvisoSinCorreo $Dominio
    }

    Auditar-SPF $Dominio
    Auditar-DKIM $Dominio
    Auditar-DMARC $Dominio
    Auditar-DANE $Dominio
    Mostrar-Resumen $Dominio
}

Main
