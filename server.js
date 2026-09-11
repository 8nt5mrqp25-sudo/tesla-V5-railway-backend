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
const BILFORDELING_APP_URL = (process.env.BILFORDELING_APP_URL || "https://bilfordeling-aage.age-sonstebo.chatgpt.site").trim().replace(/\/$/, "");
const SUPABASE_URL = (process.env.SUPABASE_URL || "").trim().replace(/\/$/, "");
const SUPABASE_SERVICE_ROLE_KEY = (process.env.SUPABASE_SERVICE_ROLE_KEY || "").trim();
const TOKEN_ENCRYPTION_KEY = (process.env.TOKEN_ENCRYPTION_KEY || TESLA_CLIENT_SECRET).trim();
const TRACKER_ENABLED = !["0", "false", "off", "no"].includes(
  String(process.env.TRACKER_ENABLED || "true").trim().toLowerCase()
);
const TRACKER_PARKED_MS = Math.max(60000, Number(process.env.TRACKER_PARKED_MS || 600000));
const TRACKER_ACTIVE_MS = Math.max(30000, Number(process.env.TRACKER_ACTIVE_MS || 60000));


const TESLA_AUTH = "https://auth.tesla.com";
const TESLA_API = "https://fleet-api.prd.eu.vn.cloud.tesla.com";
const VEHICLE_DATA_ENDPOINTS = "charge_state%3Bclimate_state%3Bdrive_state%3Blocation_data%3Bvehicle_config%3Bvehicle_state";


let savedToken = null;
let tokenLoadPromise = null;
const pkceStore = new Map();
let cachedVehicle = null;
let trackerTimer = null;
let trackerRunning = false;
const trackerRuntime = {
  lastPollAt: null,
  lastSuccessAt: null,
  lastError: null,
  activeTrip: false,
  activeDriver: null,
  nextPollSeconds: null
};


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

function tokenCryptoKey() {
  if (!TOKEN_ENCRYPTION_KEY) throw new Error("TOKEN_ENCRYPTION_KEY eller TESLA_CLIENT_SECRET mangler");
  return crypto.createHash("sha256").update(TOKEN_ENCRYPTION_KEY).digest();
}

function encryptToken(token) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", tokenCryptoKey(), iv);
  const ciphertext = Buffer.concat([
    cipher.update(JSON.stringify(token), "utf8"),
    cipher.final()
  ]);
  const tag = cipher.getAuthTag();
  return [iv, tag, ciphertext].map(x => x.toString("base64url")).join(".");
}

function decryptToken(payload) {
  const [ivRaw, tagRaw, dataRaw] = String(payload || "").split(".");
  if (!ivRaw || !tagRaw || !dataRaw) throw new Error("Ugyldig lagret Tesla-token");
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    tokenCryptoKey(),
    Buffer.from(ivRaw, "base64url")
  );
  decipher.setAuthTag(Buffer.from(tagRaw, "base64url"));
  const clear = Buffer.concat([
    decipher.update(Buffer.from(dataRaw, "base64url")),
    decipher.final()
  ]).toString("utf8");
  return JSON.parse(clear);
}

async function supabaseRequest(path, options = {}) {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    throw new Error("Supabase er ikke konfigurert i Railway");
  }
  const response = await fetch(`${SUPABASE_URL}/rest/v1/${path}`, {
    ...options,
    headers: {
      apikey: SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
      "Content-Type": "application/json",
      ...(options.headers || {})
    }
  });
  const { json, raw } = await safeJson(response);
  if (!response.ok) throw new Error(`Supabase ${response.status}: ${raw.slice(0, 900)}`);
  return json;
}

async function persistTeslaToken() {
  if (!savedToken || !SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) return;
  await supabaseRequest("bf_oauth_tokens?on_conflict=id", {
    method: "POST",
    headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
    body: JSON.stringify({
      id: "tesla",
      encrypted_payload: encryptToken(savedToken),
      updated_at: new Date().toISOString()
    })
  });
}

async function loadTeslaToken() {
  if (savedToken) return savedToken;
  if (!tokenLoadPromise) {
    tokenLoadPromise = (async () => {
      if (SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY) {
        try {
          const rows = await supabaseRequest(
            "bf_oauth_tokens?id=eq.tesla&select=encrypted_payload&limit=1"
          );
          if (Array.isArray(rows) && rows[0]?.encrypted_payload) {
            savedToken = decryptToken(rows[0].encrypted_payload);
            return savedToken;
          }
        } catch (error) {
          console.warn("Kunne ikke hente Tesla-token fra Supabase:", error.message);
        }
      }

      const refreshToken = (process.env.TESLA_REFRESH_TOKEN || "").trim();
      if (refreshToken) {
        savedToken = { access_token: "", refresh_token: refreshToken, expires_at: 0 };
        return savedToken;
      }
      return null;
    })().finally(() => { tokenLoadPromise = null; });
  }
  return tokenLoadPromise;
}


app.get("/", (req, res) => res.send("Bilfordeling Tesla backend v15"));


app.get("/health", (req, res) => {
  res.json({
    ok: true,
    version: "15.0-location-data",
    client: !!TESLA_CLIENT_ID,
    secret: !!TESLA_CLIENT_SECRET,
    google: !!GOOGLE_API_KEY,
    supabase: !!SUPABASE_URL && !!SUPABASE_SERVICE_ROLE_KEY,
    persistentTeslaToken: !!SUPABASE_URL && !!SUPABASE_SERVICE_ROLE_KEY,
    tracker: {
      enabled: TRACKER_ENABLED,
      activeTrip: trackerRuntime.activeTrip,
      activeDriver: trackerRuntime.activeDriver,
      lastPollAt: trackerRuntime.lastPollAt,
      lastSuccessAt: trackerRuntime.lastSuccessAt,
      lastError: trackerRuntime.lastError,
      nextPollSeconds: trackerRuntime.nextPollSeconds
    },
    backendUrl: BACKEND_URL,
    appUrl: APP_URL,
    endpoints: [
      "/auth/tesla",
      "/api/tesla-live",
      "/api/bilfordeling/status",
      "/api/bilfordeling/trips",
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

    await persistTeslaToken();


    res.redirect(`${APP_URL}?tesla=connected`);
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});


async function getTeslaToken() {
  await loadTeslaToken();
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

  await persistTeslaToken();


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
  if (cachedVehicle) return cachedVehicle;
  const d = await teslaFetch("/api/1/vehicles");
  const v = d.response && d.response[0];
  if (!v) throw new Error("Fant ingen Tesla");
  cachedVehicle = v;
  return cachedVehicle;
}

function haversineMeters(lat1, lon1, lat2, lon2) {
  const rad = value => value * Math.PI / 180;
  const dLat = rad(lat2 - lat1);
  const dLon = rad(lon2 - lon1);
  const a = Math.sin(dLat / 2) ** 2 +
    Math.cos(rad(lat1)) * Math.cos(rad(lat2)) * Math.sin(dLon / 2) ** 2;
  return 6371000 * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

async function configuredDrivers() {
  const rows = await supabaseRequest(
    "bf_drivers?active=eq.true&select=name,home_address,latitude,longitude,radius_meters"
  );
  return Array.isArray(rows) ? rows : [];
}

function homeAtPosition(drivers, latitude, longitude) {
  if (!Number.isFinite(latitude) || !Number.isFinite(longitude)) return null;
  const matches = drivers.map(driver => ({
    ...driver,
    distanceMeters: haversineMeters(
      latitude,
      longitude,
      Number(driver.latitude),
      Number(driver.longitude)
    )
  })).filter(driver => driver.distanceMeters <= Number(driver.radius_meters || 75));
  matches.sort((a, b) => a.distanceMeters - b.distanceMeters);
  return matches[0] || null;
}

async function loadTrackerState() {
  const rows = await supabaseRequest(
    "bf_tracker_state?id=eq.tesla&select=state&limit=1"
  );
  return Array.isArray(rows) && rows[0]?.state ? rows[0].state : {};
}

async function saveTrackerState(state) {
  await supabaseRequest("bf_tracker_state?on_conflict=id", {
    method: "POST",
    headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
    body: JSON.stringify({
      id: "tesla",
      state,
      updated_at: new Date().toISOString()
    })
  });
}

async function createTrip(driver, snapshot, startedAt) {
  const rows = await supabaseRequest("bf_trips", {
    method: "POST",
    headers: { Prefer: "return=representation" },
    body: JSON.stringify({
      started_at: startedAt || snapshot.observedAt,
      driver,
      start_latitude: snapshot.latitude,
      start_longitude: snapshot.longitude,
      start_odometer_km: snapshot.odometerKm,
      detection: "automatic"
    })
  });
  return Array.isArray(rows) ? rows[0] : rows;
}

async function closeTrip(id, snapshot, startOdometerKm) {
  const distanceKm = Number.isFinite(snapshot.odometerKm) && Number.isFinite(startOdometerKm)
    ? Math.max(0, snapshot.odometerKm - startOdometerKm)
    : null;
  const rows = await supabaseRequest(`bf_trips?id=eq.${encodeURIComponent(id)}`, {
    method: "PATCH",
    headers: { Prefer: "return=representation" },
    body: JSON.stringify({
      ended_at: snapshot.observedAt,
      end_latitude: snapshot.latitude,
      end_longitude: snapshot.longitude,
      end_odometer_km: snapshot.odometerKm,
      distance_km: distanceKm
    })
  });
  return Array.isArray(rows) ? rows[0] : rows;
}

async function trackerVehicleSnapshot() {
  const vehicle = await firstVehicle();
  const id = vehicle.id_s || vehicle.id;
  const data = await teslaFetch(`/api/1/vehicles/${id}/vehicle_data?endpoints=${VEHICLE_DATA_ENDPOINTS}`);
  const response = data.response || {};
  const drive = response.drive_state || {};
  const vehicleState = response.vehicle_state || {};
  const latitude = drive.latitude == null ? null : Number(drive.latitude);
  const longitude = drive.longitude == null ? null : Number(drive.longitude);
  return {
    observedAt: new Date().toISOString(),
    latitude: Number.isFinite(latitude) ? latitude : null,
    longitude: Number.isFinite(longitude) ? longitude : null,
    speedKmh: drive.speed == null ? null : Number(drive.speed) * 1.60934,
    shiftState: drive.shift_state ?? null,
    odometerKm: vehicleState.odometer == null ? null : Number(vehicleState.odometer) * 1.60934
  };
}

function parked(snapshot) {
  const gearParked = snapshot.shiftState == null || snapshot.shiftState === "P";
  const speedParked = snapshot.speedKmh == null || snapshot.speedKmh < 1;
  return gearParked && speedParked;
}

function previousSnapshot(state) {
  return {
    observedAt: state.lastObservedAt || new Date().toISOString(),
    latitude: Number.isFinite(state.lastLatitude) ? state.lastLatitude : null,
    longitude: Number.isFinite(state.lastLongitude) ? state.lastLongitude : null,
    odometerKm: Number.isFinite(state.lastOdometerKm) ? state.lastOdometerKm : null
  };
}

function scheduleTracker(delayMs) {
  if (!TRACKER_ENABLED) return;
  clearTimeout(trackerTimer);
  trackerRuntime.nextPollSeconds = Math.round(delayMs / 1000);
  trackerTimer = setTimeout(runTrackerTick, delayMs);
}

function requireBilfordelingOrigin(req, res, next) {
  const origin = String(req.get("origin") || "").replace(/\/$/, "");
  const referer = String(req.get("referer") || "");
  if (origin === BILFORDELING_APP_URL || referer.startsWith(`${BILFORDELING_APP_URL}/`)) {
    return next();
  }
  return res.status(403).json({ ok: false, error: "Kun tilgjengelig fra Bilfordeling-appen" });
}

function monthRange(month) {
  if (!/^\d{4}-\d{2}$/.test(month)) throw new Error("Ugyldig måned");
  const [year, monthNumber] = month.split("-").map(Number);
  if (monthNumber < 1 || monthNumber > 12) throw new Error("Ugyldig måned");
  const start = new Date(Date.UTC(year, monthNumber - 1, 1));
  const end = new Date(Date.UTC(year, monthNumber, 1));
  return { start: start.toISOString(), end: end.toISOString() };
}

app.get("/api/bilfordeling/status", requireBilfordelingOrigin, async (req, res) => {
  try {
    const state = await loadTrackerState();
    res.json({
      ok: true,
      tracker: {
        enabled: TRACKER_ENABLED,
        activeTrip: !!state.activeTripId,
        activeDriver: state.activeDriver || null,
        lastObservedAt: state.lastObservedAt || null,
        lastHome: state.lastHome || null
      }
    });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.get("/api/bilfordeling/trips", requireBilfordelingOrigin, async (req, res) => {
  try {
    const month = String(req.query.month || "");
    const { start, end } = monthRange(month);
    const rows = await supabaseRequest(
      `bf_trips?started_at=gte.${encodeURIComponent(start)}` +
      `&started_at=lt.${encodeURIComponent(end)}` +
      "&select=id,started_at,ended_at,driver,distance_km,detection" +
      "&order=started_at.desc"
    );
    res.json({ ok: true, trips: Array.isArray(rows) ? rows : [] });
  } catch (error) {
    res.status(400).json({ ok: false, error: error.message });
  }
});

app.patch("/api/bilfordeling/trips/:id", requireBilfordelingOrigin, async (req, res) => {
  try {
    const id = String(req.params.id || "");
    const driver = String(req.body?.driver || "");
    if (!/^\d+$/.test(id)) throw new Error("Ugyldig tur");
    const drivers = await configuredDrivers();
    if (!drivers.some(item => item.name === driver)) throw new Error("Ugyldig fører");
    const rows = await supabaseRequest(`bf_trips?id=eq.${encodeURIComponent(id)}`, {
      method: "PATCH",
      headers: { Prefer: "return=representation" },
      body: JSON.stringify({ driver })
    });
    const trip = Array.isArray(rows) ? rows[0] : rows;
    if (!trip) return res.status(404).json({ ok: false, error: "Turen ble ikke funnet" });
    res.json({ ok: true, trip });
  } catch (error) {
    res.status(400).json({ ok: false, error: error.message });
  }
});

async function runTrackerTick() {
  if (!TRACKER_ENABLED || trackerRunning) return;
  trackerRunning = true;
  trackerRuntime.lastPollAt = new Date().toISOString();
  let nextDelay = TRACKER_PARKED_MS;

  try {
    const [snapshot, drivers, storedState] = await Promise.all([
      trackerVehicleSnapshot(),
      configuredDrivers(),
      loadTrackerState()
    ]);
    const state = storedState && typeof storedState === "object" ? storedState : {};
    const currentHome = homeAtPosition(drivers, snapshot.latitude, snapshot.longitude);
    let activeTripId = state.activeTripId || null;
    let activeDriver = state.activeDriver || null;
    let activeStartOdometerKm = Number.isFinite(state.activeStartOdometerKm)
      ? state.activeStartOdometerKm
      : null;
    const priorHome = state.lastHome || null;

    if (!activeTripId && priorHome && currentHome && currentHome.name !== priorHome) {
      const start = previousSnapshot(state);
      const trip = await createTrip(priorHome, start, start.observedAt);
      activeTripId = trip?.id || null;
      activeDriver = priorHome;
      activeStartOdometerKm = start.odometerKm;
      if (activeTripId) {
        await closeTrip(activeTripId, snapshot, activeStartOdometerKm);
        activeTripId = null;
        activeDriver = null;
        activeStartOdometerKm = null;
      }
    } else if (!activeTripId && priorHome && !currentHome &&
      Number.isFinite(snapshot.latitude) && Number.isFinite(snapshot.longitude)) {
      const start = previousSnapshot(state);
      const trip = await createTrip(priorHome, start, start.observedAt);
      activeTripId = trip?.id || null;
      activeDriver = priorHome;
      activeStartOdometerKm = start.odometerKm;
    }

    if (activeTripId && currentHome && parked(snapshot)) {
      await closeTrip(activeTripId, snapshot, activeStartOdometerKm);
      activeTripId = null;
      activeDriver = null;
      activeStartOdometerKm = null;
    }

    const newState = {
      ...state,
      lastObservedAt: snapshot.observedAt,
      lastLatitude: snapshot.latitude,
      lastLongitude: snapshot.longitude,
      lastOdometerKm: snapshot.odometerKm,
      lastHome: !activeTripId && currentHome ? currentHome.name : priorHome,
      activeTripId,
      activeDriver,
      activeStartOdometerKm,
      consecutiveFailures: 0
    };
    await saveTrackerState(newState);

    trackerRuntime.lastSuccessAt = snapshot.observedAt;
    trackerRuntime.lastError = null;
    trackerRuntime.activeTrip = !!activeTripId;
    trackerRuntime.activeDriver = activeDriver;
    nextDelay = activeTripId ? TRACKER_ACTIVE_MS : TRACKER_PARKED_MS;
  } catch (error) {
    trackerRuntime.lastError = String(error.message || error).slice(0, 240);
    console.warn("Bilfordeling tracker:", trackerRuntime.lastError);
    nextDelay = trackerRuntime.activeTrip ? TRACKER_ACTIVE_MS : TRACKER_PARKED_MS;
  } finally {
    trackerRunning = false;
    scheduleTracker(nextDelay);
  }
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
    const d = await teslaFetch(`/api/1/vehicles/${id}/vehicle_data?endpoints=${VEHICLE_DATA_ENDPOINTS}`);
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


app.listen(PORT, () => {
  console.log("Bilfordeling Tesla backend v15 on port " + PORT);
  if (TRACKER_ENABLED) scheduleTracker(15000);
});
