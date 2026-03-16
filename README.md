This script performs an email authentication audit, 
checking SPF, DKIM, DMARC, MX, and DANE/TLSA records for a given domain.
It provides a summary of the findings and recommendations for improving email security.

```
./email-audit.sh protonmail.ch
./email-audit.sh posteo.de
./email-audit.sh mailbox.org
./email-audit.sh gmail.com
./email-audit.sh outlook.com
```

El que mejor nota saca es `protonmail.ch` porque tiene SPF, DKIM, DMARC con reject, DNSSEC y TLSA todo bien configurado. 
Seguido de `posteo.de`. Son los dos "alumnos aventajados" del correo seguro.
Los grandes (Gmail, Outlook) fallan en DANE porque Google no soporta DANE (solo MTA-STS) PrivSec, y Microsoft lo ha ido añadiendo gradualmente pero sin DNSSEC en todos sus dominios.

<img width="599" height="909" alt="imagen" src="https://github.com/user-attachments/assets/e3c1b012-8ae9-4f20-916e-ee86c282e3e2" />

<img width="554" height="701" alt="imagen" src="https://github.com/user-attachments/assets/8dc8769a-6c74-432b-bfc2-2dd989074d76" />


# simplecheckmail
Basic checks spf and dmark
Checking SPF, DKIM, DMARC, MX, and DANE/TLSA records for a given domain.
It provides a summary of the findings and recommendations for improving email security.
