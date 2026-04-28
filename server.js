import express from "express";
import cors from "cors";
import crypto from "crypto";

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 8080;

const APP_URL = process.env.APP_URL || "https://teslaoptimizer.netlify.app";
const BACKEND_URL =
  process.env.BACKEND_URL ||
  "https://tesla-v5-railway-backend-production.up.railway.app";

const TESLA_CLIENT_ID = process.env.TESLA_CLIENT_ID || "";
const TESLA_CLIENT_SECRET = process.env.TESLA_CLIENT_SECRET || "";

app.use(cors({ origin: true, credentials: true }));

let savedToken = null;
const stateStore = new Map();

function b64url(buf) {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function sha256(text) {
  return b64url(crypto.createHash("sha256").update(text).digest());
}

app.get("/", (req, res) => {
  res.send("Tesla V5 backend running");
});

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    service: "tesla-v5-railway-backend",
    teslaClientConfigured: !!TESLA_CLIENT_ID,
    teslaSecretConfigured: !!TESLA_CLIENT_SECRET,
    backendUrl: BACKEND_URL
  });
});

app.get("/auth/login", (req, res) => {
  res.redirect("/auth/tesla");
});

app.get("/auth/tesla", (req, res) => {
  if (!TESLA_CLIENT_ID) {
    return res.status(500).send("TESLA_CLIENT_ID mangler i Railway Variables");
  }

  const state = crypto.randomBytes(16).toString("hex");
  const verifier = b64url(crypto.randomBytes(64));
  const challenge = sha256(verifier);

  stateStore.set(state, verifier);

  const params = new URLSearchParams({
    client_id: TESLA_CLIENT_ID,
    response_type: "code",
    redirect_uri: `${BACKEND_URL}/auth/callback`,
    scope: "openid offline_access vehicle_device_data vehicle_location vehicle_cmds",
    state,
    code_challenge: challenge,
    code_challenge_method: "S256"
  });

  res.redirect(`https://auth.tesla.com/oauth2/v3/authorize?${params}`);
});

app.get("/auth/callback", async (req, res) => {
  try {
    const { code, state } = req.query;

    if (!code || !state) {
      return res.status(400).send("Mangler code/state fra Tesla");
    }

    const verifier = stateStore.get(String(state));
    if (!verifier) {
      return res.status(400).send("Ugyldig/utløpt state. Start på /auth/tesla igjen.");
    }

    stateStore.delete(String(state));

    const body = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: TESLA_CLIENT_ID,
      code: String(code),
      redirect_uri: `${BACKEND_URL}/auth/callback`,
      code_verifier: verifier
    });

    if (TESLA_CLIENT_SECRET) {
      body.set("client_secret", TESLA_CLIENT_SECRET);
    }

    const r = await fetch("https://auth.tesla.com/oauth2/v3/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body
    });

    const data = await r.json();

    if (!r.ok) {
      return res.status(500).json({
        ok: false,
        error: "Tesla token-feil",
        details: data
      });
    }

    savedToken = {
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      expires_at: Date.now() + (data.expires_in || 3600) * 1000
    };

    res.redirect(`${APP_URL}?tesla=connected`);
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

async function getAccessToken() {
  if (!savedToken) throw new Error("Tesla er ikke koblet enda");

  if (Date.now() < savedToken.expires_at - 120000) {
    return savedToken.access_token;
  }

  const body = new URLSearchParams({
    grant_type: "refresh_token",
    client_id: TESLA_CLIENT_ID,
    refresh_token: savedToken.refresh_token
  });

  if (TESLA_CLIENT_SECRET) {
    body.set("client_secret", TESLA_CLIENT_SECRET);
  }

  const r = await fetch("https://auth.tesla.com/oauth2/v3/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  });

  const data = await r.json();

  if (!r.ok) {
    throw new Error("Kunne ikke fornye Tesla-token");
  }

  savedToken = {
    access_token: data.access_token,
    refresh_token: data.refresh_token || savedToken.refresh_token,
    expires_at: Date.now() + (data.expires_in || 3600) * 1000
  };

  return savedToken.access_token;
}

async function teslaGet(path) {
  const token = await getAccessToken();

  const r = await fetch(`https://fleet-api.prd.eu.vn.cloud.tesla.com${path}`, {
    headers: { Authorization: `Bearer ${token}` }
  });

  const data = await r.json();

  if (!r.ok) {
    throw new Error(JSON.stringify(data));
  }

  return data;
}

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
    const vehicle = vehicles.response?.[0];

    if (!vehicle) {
      return res.status(404).json({ ok: false, error: "Fant ingen bil" });
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

    const vals = Object.values(tpms).filter(v => typeof v === "number");
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
    res.status(500).json({ ok: false, connected: false, error: err.message });
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
  console.log(`Tesla V5 backend running on port ${PORT}`);
});
