const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const fetch = require("node-fetch");

const app = express();
app.use(express.json());
app.use(cors({ origin: true }));

const PORT = process.env.PORT || 8080;

const CLIENT_ID = process.env.TESLA_CLIENT_ID || "";
const CLIENT_SECRET = process.env.TESLA_CLIENT_SECRET || "";

const BACKEND_URL =
  process.env.BACKEND_URL ||
  "https://tesla-v5-railway-backend-production.up.railway.app";

const APP_URL =
  process.env.APP_URL ||
  "https://teslaoptimizer.netlify.app";

const DOMAIN = "teslaoptimizer.netlify.app";

const TESLA_AUTH = "https://auth.tesla.com";
const TESLA_PARTNER_AUTH = "https://fleet-auth.prd.vn.cloud.tesla.com";
const TESLA_API = "https://fleet-api.prd.eu.vn.cloud.tesla.com";
const TESLA_AUDIENCE = "https://fleet-api.prd.eu.vn.cloud.tesla.com";

let savedToken = null;
const pkceStore = new Map();

function base64url(buf) {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function sha256(text) {
  return base64url(crypto.createHash("sha256").update(text).digest());
}

async function readJsonSafe(response) {
  const raw = await response.text();
  try {
    return { json: JSON.parse(raw), raw };
  } catch {
    return { json: null, raw };
  }
}

app.get("/", (req, res) => {
  res.send("Tesla backend running");
});

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    client: !!CLIENT_ID,
    secret: !!CLIENT_SECRET,
    backendUrl: BACKEND_URL,
    appUrl: APP_URL,
    domain: DOMAIN
  });
});

app.get("/auth/login", (req, res) => res.redirect("/auth/tesla"));
app.get("/api/login", (req, res) => res.redirect("/auth/tesla"));

app.get("/auth/tesla", (req, res) => {
  if (!CLIENT_ID) {
    return res.status(500).send("TESLA_CLIENT_ID mangler i Railway Variables");
  }

  const state = crypto.randomBytes(16).toString("hex");
  const verifier = base64url(crypto.randomBytes(64));
  const challenge = sha256(verifier);

  pkceStore.set(state, verifier);

  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    response_type: "code",
    redirect_uri: `${BACKEND_URL}/auth/callback`,
    scope: "openid offline_access vehicle_device_data vehicle_location vehicle_cmds",
    state,
    code_challenge: challenge,
    code_challenge_method: "S256"
  });

  res.redirect(`${TESLA_AUTH}/oauth2/v3/authorize?${params.toString()}`);
});

app.get("/auth/callback", async (req, res) => {
  try {
    const { code, state } = req.query;

    if (!code || !state) {
      return res.status(400).send("Mangler code/state fra Tesla. Start fra /auth/tesla.");
    }

    const verifier = pkceStore.get(String(state));
    if (!verifier) {
      return res.status(400).send("Ugyldig/utløpt state. Start på /auth/tesla igjen.");
    }

    pkceStore.delete(String(state));

    const body = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      code: String(code),
      redirect_uri: `${BACKEND_URL}/auth/callback`,
      code_verifier: verifier
    });

    const r = await fetch(`${TESLA_AUTH}/oauth2/v3/token`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
        "User-Agent": "Mozilla/5.0 TeslaOptimizer/1.0"
      },
      body
    });

    const { json, raw } = await readJsonSafe(r);

    if (!json) {
      return res.status(500).send(
        "Tesla svarte ikke med JSON.<br>Status: " +
          r.status +
          "<br><pre>" +
          raw.slice(0, 1500) +
          "</pre>"
      );
    }

    if (!r.ok) {
      return res.status(500).json({
        ok: false,
        error: "Tesla token-feil",
        details: json
      });
    }

    savedToken = {
      access_token: json.access_token,
      refresh_token: json.refresh_token,
      expires_at: Date.now() + (json.expires_in || 3600) * 1000
    };

    res.redirect(`${APP_URL}?tesla=connected`);
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

async function getPartnerToken() {
  const body = new URLSearchParams({
    grant_type: "client_credentials",
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    scope: "openid offline_access vehicle_device_data vehicle_location vehicle_cmds",
    audience: TESLA_AUDIENCE
  });

  const r = await fetch(`${TESLA_PARTNER_AUTH}/oauth2/v3/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json"
    },
    body
  });

  const { json, raw } = await readJsonSafe(r);

  if (!json) {
    throw new Error("Partner-token svarte ikke med JSON: " + raw.slice(0, 800));
  }

  if (!r.ok) {
    throw new Error("Partner-token feil: " + JSON.stringify(json));
  }

  return json.access_token;
}

async function getAccessToken() {
  if (!savedToken) {
    throw new Error("Tesla er ikke koblet. Åpne /auth/tesla først.");
  }

  if (Date.now() < savedToken.expires_at - 120000) {
    return savedToken.access_token;
  }

  const body = new URLSearchParams({
    grant_type: "refresh_token",
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    refresh_token: savedToken.refresh_token
  });

  const r = await fetch(`${TESLA_AUTH}/oauth2/v3/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
      "User-Agent": "Mozilla/5.0 TeslaOptimizer/1.0"
    },
    body
  });

  const { json, raw } = await readJsonSafe(r);

  if (!json) {
    throw new Error("Tesla svarte ikke med JSON: " + raw.slice(0, 800));
  }

  if (!r.ok) {
    throw new Error("Kunne ikke fornye Tesla-token: " + JSON.stringify(json));
  }

  savedToken = {
    access_token: json.access_token,
    refresh_token: json.refresh_token || savedToken.refresh_token,
    expires_at: Date.now() + (json.expires_in || 3600) * 1000
  };

  return savedToken.access_token;
}

async function teslaGet(path) {
  const token = await getAccessToken();

  const r = await fetch(`${TESLA_API}${path}`, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json"
    }
  });

  const { json, raw } = await readJsonSafe(r);

  if (!json) {
    throw new Error("Tesla API svarte ikke med JSON: " + raw.slice(0, 800));
  }

  if (!r.ok) {
    throw new Error(JSON.stringify(json));
  }

  return json;
}

app.get("/api/register-partner", async (req, res) => {
  try {
    const partnerToken = await getPartnerToken();

    const r = await fetch(`${TESLA_API}/api/1/partner_accounts`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${partnerToken}`,
        "Content-Type": "application/json",
        Accept: "application/json"
      },
      body: JSON.stringify({ domain: DOMAIN })
    });

    const { json, raw } = await readJsonSafe(r);

    if (!json) {
      return res.status(500).send(
        "Tesla register svarte ikke med JSON.<br>Status: " +
          r.status +
          "<br><pre>" +
          raw.slice(0, 1500) +
          "</pre>"
      );
    }

    res.status(r.status).json({
      ok: r.ok,
      status: r.status,
      response: json
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get("/api/vehicles", async (req, res) => {
  try {
    const data = await teslaGet("/api/1/vehicles");
    res.json({ ok: true, vehicles: data.response || [] });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get("/api/tesla-live", async (req, res) => {
  try {
    const vehicles = await teslaGet("/api/1/vehicles");
    const vehicle = vehicles.response && vehicles.response[0];

    if (!vehicle) {
      return res.status(404).json({
        ok: false,
        connected: false,
        error: "Fant ingen Tesla på kontoen"
      });
    }

    const id = vehicle.id_s || vehicle.id;

    const data = await teslaGet(
      `/api/1/vehicles/${id}/vehicle_data?endpoints=charge_state;drive_state;vehicle_state;climate_state`
    );

    const r = data.response || {};
    const charge = r.charge_state || {};
    const drive = r.drive_state || {};
    const vehicleState = r.vehicle_state || {};
    const climate = r.climate_state || {};

    const tpms = {
      fl: vehicleState.tpms_pressure_fl ?? null,
      fr: vehicleState.tpms_pressure_fr ?? null,
      rl: vehicleState.tpms_pressure_rl ?? null,
      rr: vehicleState.tpms_pressure_rr ?? null
    };

    const vals = Object.values(tpms).filter((v) => typeof v === "number");
    const tpmsAvgBar = vals.length
      ? vals.reduce((a, b) => a + b, 0) / vals.length
      : null;

    res.json({
      ok: true,
      connected: true,
      vehicle: {
        id,
        name: vehicle.display_name || vehicle.vehicle_name || "Tesla"
      },
      telemetry: {
        batteryLevel: charge.battery_level ?? null,
        usableBatteryLevel: charge.usable_battery_level ?? null,
        idealRangeKm: charge.ideal_battery_range
          ? charge.ideal_battery_range * 1.60934
          : null,
        ratedRangeKm: charge.battery_range
          ? charge.battery_range * 1.60934
          : null,
        chargingState: charge.charging_state ?? null,
        chargerPowerKw: charge.charger_power ?? null,
        vehicleSpeedKmh: drive.speed ? drive.speed * 1.60934 : null,
        latitude: drive.latitude ?? null,
        longitude: drive.longitude ?? null,
        shiftState: drive.shift_state ?? null,
        outsideTemp: climate.outside_temp ?? null,
        insideTemp: climate.inside_temp ?? null,
        tpmsAvgBar,
        tpms,
        timestamp: new Date().toISOString()
      }
    });
  } catch (err) {
    res.status(500).json({
      ok: false,
      connected: false,
      error: err.message
    });
  }
});

app.get("/api/tesla-demo", (req, res) => {
  res.json({
    ok: true,
    connected: false,
    mode: "demo",
    telemetry: {
      batteryLevel: 62,
      usableBatteryLevel: 60,
      idealRangeKm: 318,
      ratedRangeKm: 300,
      vehicleSpeedKmh: 74,
      latitude: 59.489,
      longitude: 8.633,
      outsideTemp: 5,
      insideTemp: 21,
      tpmsAvgBar: 2.9,
      tpms: { fl: 2.9, fr: 2.9, rl: 2.8, rr: 2.9 },
      chargingState: "Disconnected",
      chargerPowerKw: 0,
      timestamp: new Date().toISOString()
    }
  });
});

app.listen(PORT, () => {
  console.log("Tesla backend running on port " + PORT);
});
