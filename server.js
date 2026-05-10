const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const fetch = require("node-fetch");


const app = express();
app.use(express.json({ limit: "5mb" }));
app.use(cors({ origin: true }));


const PORT = process.env.PORT || 8080;
const TESLA_CLIENT_ID = (process.env.TESLA_CLIENT_ID || "").trim();
const TESLA_CLIENT_SECRET = (process.env.TESLA_CLIENT_SECRET || "").trim();
const GOOGLE_API_KEY = (process.env.GOOGLE_API_KEY || "").trim();
const BACKEND_URL = (process.env.BACKEND_URL || "https://tesla-v5-railway-backend-production.up.railway.app").trim();
const APP_URL = (process.env.APP_URL || "https://teslaoptimizer.netlify.app").trim();


const TESLA_AUTH = "https://auth.tesla.com";
const TESLA_API = "https://fleet-api.prd.eu.vn.cloud.tesla.com";


let savedToken = null;
const pkceStore = new Map();


function b64(buf) {
  return Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function sha256(txt) {
  return b64(crypto.createHash("sha256").update(txt).digest());
}
async function safeJson(resp) {
  const raw = await resp.text();
  try { return { json: JSON.parse(raw), raw }; }
  catch { return { json: null, raw }; }
}


app.get("/", (req, res) => res.send("Tesla TurOptimal V11 LIVE CHARGER WATCH backend"));


app.get("/health", (req, res) => {
  res.json({
    ok: true,
    version: "11.0-live-charger-watch",
    client: !!TESLA_CLIENT_ID,
    secret: !!TESLA_CLIENT_SECRET,
    google: !!GOOGLE_API_KEY,
    backendUrl: BACKEND_URL,
    appUrl: APP_URL,
    endpoints: [
      "/auth/tesla",
      "/api/tesla-live",
      "/api/wake",
      "/api/google-key",
      "/api/test-google"
    ]
  });
});


app.get("/api/google-key", (req, res) => {
  res.json({
    ok: !!GOOGLE_API_KEY,
    key: GOOGLE_API_KEY || null,
    keyPrefix: GOOGLE_API_KEY ? GOOGLE_API_KEY.slice(0, 8) + "..." : null
  });
});


app.get("/api/test-google", async (req, res) => {
  try {
    if (!GOOGLE_API_KEY) throw new Error("GOOGLE_API_KEY mangler i Railway");
    const input = String(req.query.input || "Kongsberg").trim();


    const url = "https://maps.googleapis.com/maps/api/place/autocomplete/json?" +
      new URLSearchParams({ input, key: GOOGLE_API_KEY, language: "no", components: "country:no" });


    const r = await fetch(url);
    const data = await r.json();


    res.json({
      ok: data.status === "OK" || data.status === "ZERO_RESULTS",
      googleStatus: data.status,
      errorMessage: data.error_message || null,
      count: (data.predictions || []).length,
      examples: (data.predictions || []).slice(0, 5).map(p => p.description)
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});


app.get("/auth/login", (req, res) => res.redirect("/auth/tesla"));
app.get("/api/login", (req, res) => res.redirect("/auth/tesla"));


app.get("/auth/tesla", (req, res) => {
  if (!TESLA_CLIENT_ID) return res.status(500).send("TESLA_CLIENT_ID mangler i Railway Variables");


  const state = crypto.randomBytes(16).toString("hex");
  const verifier = b64(crypto.randomBytes(64));
  const challenge = sha256(verifier);
  pkceStore.set(state, verifier);


  const params = new URLSearchParams({
    client_id: TESLA_CLIENT_ID,
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
    const verifier = pkceStore.get(String(state || ""));
    if (!code || !verifier) return res.status(400).send("Mangler code eller utløpt state. Start /auth/tesla igjen.");
    pkceStore.delete(String(state));


    const body = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: TESLA_CLIENT_ID,
      client_secret: TESLA_CLIENT_SECRET,
      code: String(code),
      redirect_uri: `${BACKEND_URL}/auth/callback`,
      code_verifier: verifier
    });


    const r = await fetch(`${TESLA_AUTH}/oauth2/v3/token`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
        "User-Agent": "TeslaTurOptimal/5.0"
      },
      body
    });


    const { json, raw } = await safeJson(r);
    if (!json) return res.status(500).send(raw.slice(0, 1200));
    if (!r.ok) return res.status(500).json({ ok: false, error: "Tesla token-feil", details: json });


    savedToken = {
      access_token: json.access_token,
      refresh_token: json.refresh_token,
      expires_at: Date.now() + (json.expires_in || 3600) * 1000
    };


    res.redirect(`${APP_URL}?tesla=connected`);
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});


async function getTeslaToken() {
  if (!savedToken) throw new Error("Tesla er ikke koblet. Åpne /auth/tesla først.");


  if (Date.now() < savedToken.expires_at - 120000) return savedToken.access_token;


  const body = new URLSearchParams({
    grant_type: "refresh_token",
    client_id: TESLA_CLIENT_ID,
    client_secret: TESLA_CLIENT_SECRET,
    refresh_token: savedToken.refresh_token
  });


  const r = await fetch(`${TESLA_AUTH}/oauth2/v3/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
      "User-Agent": "TeslaTurOptimal/5.0"
    },
    body
  });


  const { json, raw } = await safeJson(r);
  if (!json) throw new Error(raw.slice(0, 900));
  if (!r.ok) throw new Error(JSON.stringify(json));


  savedToken = {
    access_token: json.access_token,
    refresh_token: json.refresh_token || savedToken.refresh_token,
    expires_at: Date.now() + (json.expires_in || 3600) * 1000
  };


  return savedToken.access_token;
}


async function teslaFetch(path, opt = {}) {
  const token = await getTeslaToken();
  const r = await fetch(`${TESLA_API}${path}`, {
    ...opt,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
      "Content-Type": "application/json",
      ...(opt.headers || {})
    }
  });


  const { json, raw } = await safeJson(r);
  if (!json) throw new Error(raw.slice(0, 900));
  if (!r.ok) throw new Error(JSON.stringify(json));
  return json;
}


async function firstVehicle() {
  const d = await teslaFetch("/api/1/vehicles");
  const v = d.response && d.response[0];
  if (!v) throw new Error("Fant ingen Tesla");
  return v;
}


app.post("/api/wake", async (req, res) => {
  try {
    const v = await firstVehicle();
    const id = v.id_s || v.id;
    const d = await teslaFetch(`/api/1/vehicles/${id}/wake_up`, { method: "POST" });
    res.json({ ok: true, response: d.response || d });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});


app.get("/api/tesla-live", async (req, res) => {
  try {
    const v = await firstVehicle();
    const id = v.id_s || v.id;
    const d = await teslaFetch(`/api/1/vehicles/${id}/vehicle_data`);
    const r = d.response || {};
    const c = r.charge_state || {};
    const dr = r.drive_state || {};
    const vs = r.vehicle_state || {};
    const cl = r.climate_state || {};
    const cfg = r.vehicle_config || {};


    const tpms = {
      fl: vs.tpms_pressure_fl ?? null,
      fr: vs.tpms_pressure_fr ?? null,
      rl: vs.tpms_pressure_rl ?? null,
      rr: vs.tpms_pressure_rr ?? null
    };
    const vals = Object.values(tpms).filter(x => typeof x === "number");


    res.json({
      ok: true,
      connected: true,
      vehicle: {
        id,
        name: v.display_name || vs.vehicle_name || "Tesla",
        state: v.state || null,
        carVersion: vs.car_version || null,
        carType: cfg.car_type || null,
        wheelType: cfg.wheel_type || null,
        odometerKm: vs.odometer ? vs.odometer * 1.60934 : null
      },
      telemetry: {
        batteryLevel: c.battery_level ?? null,
        usableBatteryLevel: c.usable_battery_level ?? null,
        chargeLimitSoc: c.charge_limit_soc ?? null,
        idealRangeKm: c.ideal_battery_range ? c.ideal_battery_range * 1.60934 : null,
        ratedRangeKm: c.battery_range ? c.battery_range * 1.60934 : null,
        chargingState: c.charging_state ?? null,
        chargerPowerKw: c.charger_power ?? null,
        speedKmh: dr.speed != null ? dr.speed * 1.60934 : null,
        powerKw: dr.power ?? null,
        latitude: dr.latitude ?? null,
        longitude: dr.longitude ?? null,
        shiftState: dr.shift_state ?? null,
        outsideTemp: cl.outside_temp ?? null,
        insideTemp: cl.inside_temp ?? null,
        climateOn: cl.is_climate_on ?? null,
        tpmsAvgBar: vals.length ? vals.reduce((a, b) => a + b, 0) / vals.length : null,
        tpms,
        tpmsRecommended: {
          front: vs.tpms_rcp_front_value ?? null,
          rear: vs.tpms_rcp_rear_value ?? null
        },
        timestamp: new Date().toISOString()
      }
    });
  } catch (e) {
    res.status(500).json({ ok: false, connected: false, error: e.message });
  }
});




// ===== V10.6 PLACES API (NEW) EV METADATA PROXY =====
function simplifyEvOptionsV106(place) {
  const ev = place.evChargeOptions || {};
  const aggs = ev.connectorAggregation || [];
  let total = ev.connectorCount || null;
  let available = null;
  let maxKw = null;
  let connectorTypes = [];
  if (Array.isArray(aggs)) {
    let sum = 0, availSum = 0, hasAvail = false;
    for (const a of aggs) {
      const count = Number(a.count || 0);
      if (count) sum += count;
      if (a.availableCount !== undefined && a.availableCount !== null) {
        hasAvail = true;
        availSum += Number(a.availableCount);
      }
      const rate = Number(a.maxChargeRateKw || 0);
      if (rate) maxKw = Math.max(maxKw || 0, rate);
      if (a.type) connectorTypes.push(String(a.type).replace("EV_CONNECTOR_TYPE_", ""));
    }
    if (!total && sum) total = sum;
    if (hasAvail) available = availSum;
  }
  return { available, total, maxKw, connectorTypes: [...new Set(connectorTypes)].filter(Boolean) };
}


app.get("/api/places/ev-search", async (req, res) => {
  try {
    const key = process.env.GOOGLE_API_KEY;
    if (!key) return res.status(500).json({ error: "GOOGLE_API_KEY mangler i Railway" });
    const q = String(req.query.q || "Tesla Supercharger").slice(0, 200);
    const lat = Number(req.query.lat), lng = Number(req.query.lng);
    const body = { textQuery: q, maxResultCount: 5, includedType: "electric_vehicle_charging_station" };
    if (Number.isFinite(lat) && Number.isFinite(lng)) {
      body.locationBias = { circle: { center: { latitude: lat, longitude: lng }, radius: Number(req.query.radius || 12000) } };
    }
    const r = await fetch("https://places.googleapis.com/v1/places:searchText", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Goog-Api-Key": key,
        "X-Goog-FieldMask": "places.id,places.displayName,places.formattedAddress,places.location,places.rating,places.userRatingCount,places.regularOpeningHours,places.businessStatus,places.evChargeOptions,places.googleMapsUri"
      },
      body: JSON.stringify(body)
    });
    const data = await r.json();
    if (!r.ok) return res.status(r.status).json({ error: "Google Places feilet", details: data });
    const places = (data.places || []).map(p => ({
      id: p.id,
      name: p.displayName?.text || "",
      formattedAddress: p.formattedAddress || "",
      location: p.location || null,
      rating: p.rating || null,
      userRatingCount: p.userRatingCount || null,
      businessStatus: p.businessStatus || null,
      openNow: p.regularOpeningHours?.openNow ?? null,
      googleMapsUri: p.googleMapsUri || null,
      ev: simplifyEvOptionsV106(p)
    }));
    res.json({ places });
  } catch (err) {
    res.status(500).json({ error: String(err.message || err) });
  }
});


app.listen(PORT, () => console.log("Tesla TurOptimal V11 LIVE CHARGER WATCH backend on port " + PORT));
