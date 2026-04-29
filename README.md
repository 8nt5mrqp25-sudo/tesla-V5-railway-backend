Tesla TurOptimal V2.7 Diagnose Backend

Hva den gjør:
- Henter full /vehicle_data uten endpoint-filter
- Scanner etter speed, tpms, pressure, tire, wheel
- Nytt endpoint: /api/tesla-raw-diagnose

Test:
https://diplomatic-charisma-production-3e63.up.railway.app/health
https://diplomatic-charisma-production-3e63.up.railway.app/api/tesla-raw-diagnose

Viktig:
Denne versjonen er for diagnose av hastighet/dekktrykk.
