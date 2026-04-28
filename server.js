const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const fetch = require("node-fetch");

const app = express();
app.use(express.json());
app.use(cors({ origin: true }));

const PORT = process.env.PORT || 8080;

/* =========================
   CONFIG
========================= */

const CLIENT_ID = process.env.TESLA_CLIENT_ID;
const CLIENT_SECRET = process.env.TESLA_CLIENT_SECRET;

const BACKEND_URL =
  process.env.BACKEND_URL ||
  "https://tesla-v5-railway-backend-production.up.railway.app";

const APP_URL =
  process.env.APP_URL ||
  "https://teslaoptimizer.netlify.app";

const TESLA_AUTH = "https://auth.tesla.com";
const TESLA_API = "https://fleet-api.prd.eu.vn.cloud.tesla.com";

/* =========================
   STORAGE
========================= */

let savedToken = null;
const pkceStore = new Map();

/* =========================
   HELPERS
========================= */

function base64url(buf) {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function sha256(text) {
  return base64url(
    crypto.createHash("sha256").update(text).digest()
  );
}

/* =========================
   HEALTH
========================= */

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    client: !!CLIENT_ID,
    secret: !!CLIENT_SECRET
  });
});

/* =========================
   LOGIN
========================= */

app.get("/auth/tesla", (req, res) => {
  const state = crypto.randomBytes(16).toString("hex");
  const verifier = base64url(crypto.randomBytes(64));
  const challenge = sha256(verifier);

  pkceStore.set(state, verifier);

  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    response_type: "code",
    redirect_uri: `${BACKEND_URL}/auth/callback`,
    scope:
      "openid offline_access vehicle_device_data vehicle_location vehicle_cmds",
    state,
    code_challenge: challenge,
    code_challenge_method: "S256"
  });

  res.redirect(
    `${TESLA_AUTH}/oauth2/v3/authorize?${params.toString()}`
  );
});

/* =========================
   CALLBACK
========================= */

app.get("/auth/callback", async (req, res) => {
  try {
    const { code, state } = req.query;

    if (!code || !state) {
      return res.send("Mangler code/state");
    }

    const verifier = pkceStore.get(state);

    const body = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      code,
      redirect_uri: `${BACKEND_URL}/auth/callback`,
      code_verifier: verifier
    });

    const r = await fetch(
      `${TESLA_AUTH}/oauth2/v3/token`,
      {
        method: "POST",
        headers: {
          "Content-Type":
            "application/x-www-form-urlencoded"
        },
        body
      }
    );

    const data = await r.json();

    if (!r.ok) {
      return res.json({
        ok: false,
        error: data
      });
    }

    savedToken = {
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      expires_at:
        Date.now() + data.expires_in * 1000
    };

    res.redirect(`${APP_URL}?tesla=connected`);

  } catch (err) {
    res.send(err.message);
  }
});

/* =========================
   TOKEN
========================= */

async function getAccessToken() {
  if (!savedToken) {
    throw new Error("Ikke logget inn");
  }

  if (Date.now() < savedToken.expires_at) {
    return savedToken.access_token;
  }

  const body = new URLSearchParams({
    grant_type: "refresh_token",
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    refresh_token: savedToken.refresh_token
  });

  const r = await fetch(
    `${TESLA_AUTH}/oauth2/v3/token`,
    {
      method: "POST",
      headers: {
        "Content-Type":
          "application/x-www-form-urlencoded"
      },
      body
    }
  );

  const data = await r.json();

  savedToken.access_token = data.access_token;
  return data.access_token;
}

/* =========================
   TESLA API
========================= */

async function teslaGet(path) {
  const token = await getAccessToken();

  const r = await fetch(`${TESLA_API}${path}`, {
    headers: {
      Authorization: `Bearer ${token}`
    }
  });

  return await r.json();
}

/* =========================
   REGISTER PARTNER
========================= */

app.get("/api/register-partner", async (req, res) => {
  try {
    const token = await getAccessToken();

    const r = await fetch(
      `${TESLA_API}/api/1/partner_accounts`,
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

    res.json(data);

  } catch (err) {
    res.json({ error: err.message });
  }
});

/* =========================
   VEHICLES
========================= */

app.get("/api/vehicles", async (req, res) => {
  try {
    const data = await teslaGet("/api/1/vehicles");
    res.json(data);
  } catch (err) {
    res.json({ error: err.message });
  }
});

/* =========================
   LIVE DATA
========================= */

app.get("/api/tesla-live", async (req, res) => {
  try {
    const vehicles = await teslaGet("/api/1/vehicles");

    const vehicle = vehicles.response[0];
    const id = vehicle.id_s || vehicle.id;

    const data = await teslaGet(
      `/api/1/vehicles/${id}/vehicle_data`
    );

    res.json(data);

  } catch (err) {
    res.json({ error: err.message });
  }
});

/* =========================
   START
========================= */

app.listen(PORT, () => {
  console.log("Server kjører på port " + PORT);
});
