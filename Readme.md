# BarnevernSkann
BarnevernSkann er laget for å pushe skannede PDF-filer til fagsystemet Modulus Barn,levert av NetCompany.
Det skal brukes mot mailing-API i Modulus Barn, som krever autentisering via DigDir Maskinporten.


## Systemkrav
BarnevernSkann kan enten kjøres som skript eller bygges til et program. Begge deler krever Python 3.10 eller nyere.
Følgende Python-pakker (med alle sine systemkrav) er nødvendige for å kjøre/kompilere koden
- Requests (https://pypi.org/project/requests/)
- PyJWT (https://pypi.org/project/PyJWT/)

Følgende Python-pakker (med alle sine systemkrav) er nødvendige for lage private/public keypair
- JWCrypto (https://pypi.org/project/jwcrypto/)
- Cryptography (https://pypi.org/project/cryptography/)

For å bygge programmet kreves følgende Python-pakke
- Pyinstaller (https://pypi.org/project/pyinstaller/)


## Konfigurasjon
Oppsett for BarnevernSkann konfigureres i filen _config.json_. 
Alle felter er påkrevd utenom _maskinportenKid_, som kun brukes dersom JWK brukes til autentisering i stedet for virksomhetsssertifkat. 
Følgende felter finnes i konfigurasjonen
- "workingDirectory": "_Sti til hovedkatalog der filer skal lastes opp fra_",
- "privateKeyFile": "_Sti til privat nøkkel i PEM-format som brukes i Maskinporten-integrasjon_",
- "maskinportenKid": "_KID i Maskinporten-integrasjon_",
- "maskinportenUrl": "_URL til Maskinporten prod/test, eksempelvis https://ver2.maskinporten.no/_",
- "maskinportenScope": "_Maskinporten scope som kreves for å bruke API i Modulus Barn_",
- "maskinportenIssuer": "_Maskinporten IntegrasjonsID_",
- "modulusUrl": "_Modulus Barn URL, eksempelvis https://test.modulus-barn.no/_",
- "timeout": _Timeout skal være likt TTL i Maskinporten-integrasjonen. Tid oppgis i sekunder, eksempelvis 60._

Merk at felter skal utenom timeout skal være formatert som string med " " rundt som spesifisert i JSON-standarden.
Timeout skal være formatert som integrer.


## Bruk
BarnevernSkann kan brukes både på Windows og Linux-OS, så lenge Python 3 er installert eller det har blitt bygget som program. 
Det anbefales å sette opp regelmessig kjøring via eksempelvis Crontab eller Scheduled Task.

Katalogstrukturen i programmet skal være som følger
- .../_konfigurerbar hovedkatalog_/
  - _distrikt/barnevernstjeneste/bydel 1_/
  - _distrikt/barnevernstjeneste/bydel 2_/
  - _distrikt/barnevernstjeneste/bydel 3_/
  - .../
  - _Finished_/
  - _Failed_/
  - _Logs_/


Navn på underkataloger skal matche enhetskode i Modulus Barn der dokumentet hører hjemme, eksempelvis
- _BK-FYBD-FYBV/_ - Bergen Kommune, Fana og Ytrebygda bydel, Fana og Ytrebygda Barnevernstjeneste.
Finished, Failed og Logs vil bli opprettet automatisk ved første kjøring hvis de ikke eksisterer.

Når BarnevernSkann er kjørt vil alle skannede dokumenter dukke opp i postlisten på enhet tilsvarende navn på katalogen dokumentet lå i.
Ferdige dokumenter som er lastet opp vil bli flyttet til _Finished_.

Dokumenter som av en eller annen grunn feiler vil bli prøvd på nytt automatisk.
Feiler dokumentet igjen vil det bli flyttet til _Failed_. Det anbefales å sjekke denne mappen regelmessig for feilede dokumenter.

Alle dokumenter som lastes opp eller feiler vil bli logget i _Logs_. 
Hver gang BarnevernsSkann kjøres opprettes det en nye linjer i dagens loggfil. 
Loggingen inkluderer følgende informasjon.
- Tidsstempel for kjøringen
- Dokumentnavn
- Status
- HTTP respons fra Modulus Barn mailing API
- Eventuelle feilmeldinger

JWK og privat nøkkel for bruk i Maskinporten-integrasjon kan genereres ved å bruke generatekey.py (eller generatekey-programmet).
Dette vil generere fire filer
- Private key i PEM-format (Merk at dette er byte-output, som må konverteres til tekst ved å fjerne b'-annoteringen)
- Public key i PEM-format (Merk at dette er byte-output, som må konverteres til tekst ved å fjerne b'-annoteringen)
- Private key i JWK-format
- Public key i JWK-format


## Kompilering
BarnevernSkann kompileres ved  kjøre koden i compile.py. Dette krever at verktøyet Pyinstaller er installert og konfigurert, 
og alle de nødvendige Python-pakkene for å kjøre de forskjellige komponentene er installert.
Kompileringen kan konfigureres ved å legge til flere eller fjerne alternativer fra koden i compile.py.
Merk at Windows executable må kompileres på Windows og Linux executable må kompileres på Linux.


## Copyright
    Copyright (C) 2023 Bergen Kommune

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.