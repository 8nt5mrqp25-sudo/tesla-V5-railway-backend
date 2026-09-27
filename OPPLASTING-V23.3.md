# Bilfordeling backend V23.3 – Netlify

Denne versjonen inneholder bomprisrettelsen fra V23.2 og gir både ChatGPT Site og den nye Netlify-appen tilgang til Bilfordeling-endepunktene.

## Last opp backend

Pakk ut ZIP-filen og last opp `server.js`, `package.json` og `package-lock.json` til GitHub-repositoriet for Railway-backenden. Ingen ny SQL skal kjøres.

Etter Railway-deploy skal `/health` vise:

`23.3-bilfordeling-netlify`

Netlify-adressen er satt til:

`https://bilfordeling-aage.netlify.app`

Hvis Netlify gir appen et annet navn, legg den faktiske adressen inn som Railway-variabelen `BILFORDELING_NETLIFY_URL`.
