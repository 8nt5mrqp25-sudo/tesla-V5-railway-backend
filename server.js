
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const fetch = require("node-fetch");

const app = express();
app.use(express.json({ limit: "2mb" }));
app.use(cors({ origin: true }));

const PORT = process.env.PORT || 8080;
const CLIENT_ID = (process.env.TESLA_CLIENT_ID || "").trim();
const CLIENT_SECRET = (process.env.TESLA_CLIENT_SECRET || "").trim();
const GOOGLE_API_KEY = (process.env.GOOGLE_API_KEY || "").trim();
const BACKEND_URL = (process.env.BACKEND_URL || "https://diplomatic-charisma-production-3e63.up.railway.app").trim();
const APP_URL = (process.env.APP_URL || "https://teslaoptimizer.netlify.app").trim();

const TESLA_AUTH = "https://auth.tesla.com";
const TESLA_API = "https://fleet-api.prd.eu.vn.cloud.tesla.com";

let savedToken = null;
const pkceStore = new Map();

function b64(buf){return Buffer.from(buf).toString("base64").replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"")}
function sha256(t){return b64(crypto.createHash("sha256").update(t).digest())}
async function safeJson(r){const raw=await r.text();try{return{json:JSON.parse(raw),raw}}catch{return{json:null,raw}}}

app.get("/",(req,res)=>res.send("Tesla TurOptimal V2.7 Diagnose backend"));
app.get("/health",(req,res)=>res.json({
  ok:true, version:"2.7-diagnose",
  client:!!CLIENT_ID, secret:!!CLIENT_SECRET, google:!!GOOGLE_API_KEY,
  backendUrl:BACKEND_URL, appUrl:APP_URL,
  endpoints:["/auth/tesla","/api/tesla-live-dashboard","/api/tesla-wake","/api/tesla-raw-diagnose"]
}));

app.get("/auth/tesla",(req,res)=>{
  if(!CLIENT_ID) return res.status(500).send("TESLA_CLIENT_ID mangler");
  const state=crypto.randomBytes(16).toString("hex");
  const verifier=b64(crypto.randomBytes(64));
  const challenge=sha256(verifier);
  pkceStore.set(state,verifier);
  const p=new URLSearchParams({
    client_id:CLIENT_ID,
    response_type:"code",
    redirect_uri:`${BACKEND_URL}/auth/callback`,
    scope:"openid offline_access vehicle_device_data vehicle_location vehicle_cmds",
    state,
    code_challenge:challenge,
    code_challenge_method:"S256"
  });
  res.redirect(`${TESLA_AUTH}/oauth2/v3/authorize?${p.toString()}`);
});

app.get("/auth/login",(req,res)=>res.redirect("/auth/tesla"));
app.get("/api/login",(req,res)=>res.redirect("/auth/tesla"));

app.get("/auth/callback",async(req,res)=>{
  try{
    const {code,state}=req.query;
    if(!code||!state) return res.status(400).send("Mangler code/state");
    const verifier=pkceStore.get(String(state));
    if(!verifier) return res.status(400).send("Ugyldig/utløpt state. Start på /auth/tesla igjen.");
    pkceStore.delete(String(state));

    const body=new URLSearchParams({
      grant_type:"authorization_code",
      client_id:CLIENT_ID,
      client_secret:CLIENT_SECRET,
      code:String(code),
      redirect_uri:`${BACKEND_URL}/auth/callback`,
      code_verifier:verifier
    });

    const r=await fetch(`${TESLA_AUTH}/oauth2/v3/token`,{
      method:"POST",
      headers:{"Content-Type":"application/x-www-form-urlencoded",Accept:"application/json","User-Agent":"TeslaOptimizer/2.7"},
      body
    });
    const {json,raw}=await safeJson(r);
    if(!json) return res.status(500).send("Tesla token svarte ikke JSON: "+raw.slice(0,1000));
    if(!r.ok) return res.status(500).json({ok:false,error:"Tesla token-feil",details:json});

    savedToken={access_token:json.access_token,refresh_token:json.refresh_token,expires_at:Date.now()+(json.expires_in||3600)*1000};
    res.redirect(`${APP_URL}?tesla=connected`);
  }catch(e){res.status(500).json({ok:false,error:e.message})}
});

async function getToken(){
  if(!savedToken) throw new Error("Tesla er ikke koblet. Åpne /auth/tesla først.");
  if(Date.now()<savedToken.expires_at-120000) return savedToken.access_token;

  const body=new URLSearchParams({
    grant_type:"refresh_token",
    client_id:CLIENT_ID,
    client_secret:CLIENT_SECRET,
    refresh_token:savedToken.refresh_token
  });
  const r=await fetch(`${TESLA_AUTH}/oauth2/v3/token`,{
    method:"POST",
    headers:{"Content-Type":"application/x-www-form-urlencoded",Accept:"application/json","User-Agent":"TeslaOptimizer/2.7"},
    body
  });
  const {json,raw}=await safeJson(r);
  if(!json) throw new Error("Tesla refresh svarte ikke JSON: "+raw.slice(0,800));
  if(!r.ok) throw new Error("Kunne ikke fornye Tesla-token: "+JSON.stringify(json));

  savedToken={access_token:json.access_token,refresh_token:json.refresh_token||savedToken.refresh_token,expires_at:Date.now()+(json.expires_in||3600)*1000};
  return savedToken.access_token;
}

async function teslaFetch(path,opt={}){
  const token=await getToken();
  const r=await fetch(`${TESLA_API}${path}`,{
    ...opt,
    headers:{Authorization:`Bearer ${token}`,Accept:"application/json","Content-Type":"application/json",...(opt.headers||{})}
  });
  const {json,raw}=await safeJson(r);
  if(!json) throw new Error("Tesla API svarte ikke JSON: "+raw.slice(0,1000));
  if(!r.ok) throw new Error(JSON.stringify(json));
  return json;
}

async function firstVehicle(){
  const d=await teslaFetch("/api/1/vehicles");
  const v=d.response&&d.response[0];
  if(!v) throw new Error("Fant ingen Tesla på kontoen");
  return v;
}

function scan(obj, needles, prefix="", out=[]){
  if(obj===null || obj===undefined) return out;
  if(typeof obj!=="object") return out;
  for(const [k,v] of Object.entries(obj)){
    const path=prefix?`${prefix}.${k}`:k;
    const lower=path.toLowerCase();
    if(needles.some(n=>lower.includes(n))){
      out.push({path,value:v});
    }
    if(v && typeof v==="object") scan(v,needles,path,out);
  }
  return out;
}

function readPath(obj,path){
  return path.split(".").reduce((a,k)=>a&&a[k],obj);
}

function findFirstNumber(raw, paths){
  for(const p of paths){
    const v=readPath(raw,p);
    if(typeof v==="number") return {path:p,value:v};
  }
  return {path:null,value:null};
}

app.post("/api/tesla-wake",async(req,res)=>{
  try{
    const v=await firstVehicle();
    const id=v.id_s||v.id;
    const d=await teslaFetch(`/api/1/vehicles/${id}/wake_up`,{method:"POST"});
    res.json({ok:true,vehicle:{id,name:v.display_name||v.vehicle_name||"Tesla"},response:d.response||d});
  }catch(e){res.status(500).json({ok:false,error:e.message})}
});

app.get("/api/tesla-live-dashboard",async(req,res)=>{
  try{
    const v=await firstVehicle();
    const id=v.id_s||v.id;
    const d=await teslaFetch(`/api/1/vehicles/${id}/vehicle_data`);
    const r=d.response||{};
    const c=r.charge_state||{}, dr=r.drive_state||{}, vs=r.vehicle_state||{}, cl=r.climate_state||{};

    const speed = findFirstNumber(r,[
      "drive_state.speed",
      "vehicle_state.speed",
      "speed"
    ]);

    const tpms = {
      fl: findFirstNumber(r,["vehicle_state.tpms_pressure_fl","tpms_pressure_fl","tire_pressure_fl"]).value,
      fr: findFirstNumber(r,["vehicle_state.tpms_pressure_fr","tpms_pressure_fr","tire_pressure_fr"]).value,
      rl: findFirstNumber(r,["vehicle_state.tpms_pressure_rl","tpms_pressure_rl","tire_pressure_rl"]).value,
      rr: findFirstNumber(r,["vehicle_state.tpms_pressure_rr","tpms_pressure_rr","tire_pressure_rr"]).value
    };
    const vals=Object.values(tpms).filter(x=>typeof x==="number");

    res.json({ok:true,connected:true,diagnoseVersion:"2.7",
      vehicle:{id,name:v.display_name||v.vehicle_name||"Tesla",state:v.state||null},
      telemetry:{
        batteryLevel:c.battery_level??null,
        usableBatteryLevel:c.usable_battery_level??null,
        idealRangeKm:c.ideal_battery_range?c.ideal_battery_range*1.60934:null,
        ratedRangeKm:c.battery_range?c.battery_range*1.60934:null,
        chargingState:c.charging_state??null,
        chargerPowerKw:c.charger_power??null,
        vehicleSpeedKmh: speed.value!==null ? speed.value*1.60934 : null,
        speedSource:speed.path,
        latitude:dr.latitude??null,
        longitude:dr.longitude??null,
        shiftState:dr.shift_state??null,
        outsideTemp:cl.outside_temp??null,
        insideTemp:cl.inside_temp??null,
        tpmsAvgBar:vals.length?vals.reduce((a,b)=>a+b,0)/vals.length:null,
        tpms,
        tpmsStatus:vals.length?"reported_by_api":"not_reported_by_api",
        timestamp:new Date().toISOString()
      }
    });
  }catch(e){res.status(500).json({ok:false,connected:false,error:e.message})}
});

app.get("/api/tesla-live",(req,res)=>{req.url="/api/tesla-live-dashboard";app._router.handle(req,res)});

app.get("/api/tesla-raw-diagnose",async(req,res)=>{
  try{
    const v=await firstVehicle();
    const id=v.id_s||v.id;
    const d=await teslaFetch(`/api/1/vehicles/${id}/vehicle_data`);
    const raw=d.response||{};
    const matches=scan(raw,["speed","tpms","pressure","tire","wheel","drive_state","vehicle_state"]);
    const tpmsMatches=matches.filter(m=>String(m.path).toLowerCase().match(/tpms|pressure|tire|wheel/));
    const speedMatches=matches.filter(m=>String(m.path).toLowerCase().includes("speed"));

    res.json({
      ok:true,
      vehicle:{id,name:v.display_name||v.vehicle_name||"Tesla",state:v.state||null},
      summary:{
        totalMatches:matches.length,
        speedMatches:speedMatches.length,
        tpmsMatches:tpmsMatches.length
      },
      speedMatches,
      tpmsMatches,
      allMatches:matches,
      raw
    });
  }catch(e){res.status(500).json({ok:false,error:e.message})}
});

/* Keep route endpoint placeholder so frontend does not crash if used */
app.post("/api/route-pro-v24", async(req,res)=>{
  res.status(501).json({ok:false,error:"V2.7 diagnose backend fokuserer på Tesla rådata. Bruk V2.4 backend for rute, eller be om kombinert V2.8."});
});

app.listen(PORT,()=>console.log("Tesla TurOptimal V2.7 Diagnose backend on port "+PORT));
