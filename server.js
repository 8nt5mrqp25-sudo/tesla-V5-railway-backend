import express from "express";
import fetch from "node-fetch";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(express.json());

/* =========================
   CONFIG
========================= */

const CLIENT_ID = process.env.TESLA_CLIENT_ID;
const CLIENT_SECRET = process.env.TESLA_CLIENT_SECRET;
const REDIRECT_URI = process.env.TESLA_REDIRECT_URI;

let access_token = null;
let refresh_token = null;

/* =========================
   HEALTH
========================= */

app.get("/health", (req, res) => {
  res.json({ ok: true });
});

/* =========================
   LOGIN (redirect til Tesla)
========================= */

app.get("/api/login", (req, res) => {
  const url =
    `https://auth.tesla.com/oauth2/v3/authorize` +
    `?client_id=${CLIENT_ID}` +
    `&response_type=code` +
    `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
    `&scope=openid vehicle_device_data vehicle_cmds` +
    `&state=tesla`;

  res.redirect(url);
});

/* =========================
   CALLBACK (viktig!)
========================= */

app.get("/auth/callback", async (req, res) => {
  const { code } = req.query;

  if (!code) {
    return res.send("Mangler code fra Tesla");
  }

  try {
    const r = await fetch("https://auth.tesla.com/oauth2/v3/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        code,
        redirect_uri: REDIRECT_URI
      })
    });

    const data = await r.json();

    access_token = data.access_token;
    refresh_token = data.refresh_token;

    res.redirect("https://teslaoptimizer.netlify.app/?tesla=connected");

  } catch (err) {
    res.send("Token-feil: " + err.message);
  }
});

/* =========================
   HENT TOKEN
========================= */

async function getAccessToken() {
  if (!access_token && refresh_token) {
    const r = await fetch("https://auth.tesla.com/oauth2/v3/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        refresh_token
      })
    });

    const data = await r.json();
    access_token = data.access_token;
  }

  return access_token;
}

/* =========================
   TESLA LIVE DATA
========================= */

app.get("/api/tesla-live", async (req, res) => {
  try {
    const token = await getAccessToken();

    const r = await fetch(
      "https://fleet-api.prd.eu.vn.cloud.tesla.com/api/1/vehicles",
      {
        headers: {
          Authorization: `Bearer ${token}`
        }
      }
    );

    const data = await r.json();

    res.json({
      ok: true,
      data
    });

  } catch (err) {
    res.json({
      ok: false,
      error: err.message
    });
  }
});

/* =========================
   🔥 REGISTER PARTNER (DET DU TRENGER NÅ)
========================= */

app.get("/api/register-partner", async (req, res) => {
  try {
    const token = await getAccessToken();

    const r = await fetch(
      "https://fleet-api.prd.eu.vn.cloud.tesla.com/api/1/partner_accounts",
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          domain: "teslaoptimizer.netlify.app"
        })
      }
    );

    const data = await r.json();

    res.status(r.status).json({
      ok: r.ok,
      status: r.status,
      response: data
    });

  } catch (err) {
    res.status(500).json({
      ok: false,
      error: err.message
    });
  }
});

/* =========================
   START SERVER
========================= */

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("Server kjører på port " + PORT);
});
