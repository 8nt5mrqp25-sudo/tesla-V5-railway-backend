
const express=require("express"),cors=require("cors"),crypto=require("crypto"),fetch=require("node-fetch");
const app=express();app.use(express.json({limit:"2mb"}));app.use(cors({origin:true}));
const PORT=process.env.PORT||8080;
const CLIENT_ID=(process.env.TESLA_CLIENT_ID||"").trim();
const CLIENT_SECRET=(process.env.TESLA_CLIENT_SECRET||"").trim();
const GOOGLE_API_KEY=(process.env.GOOGLE_API_KEY||"").trim();
const BACKEND_URL=(process.env.BACKEND_URL||"https://diplomatic-charisma-production-3e63.up.railway.app").trim();
const APP_URL=(process.env.APP_URL||"https://teslaoptimizer.netlify.app").trim();
const TESLA_AUTH="https://auth.tesla.com";
const TESLA_API="https://fleet-api.prd.eu.vn.cloud.tesla.com";
let savedToken=null;const pkceStore=new Map();

function b64(buf){return Buffer.from(buf).toString("base64").replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"")}
function sha256(t){return b64(crypto.createHash("sha256").update(t).digest())}
async function safeJson(r){const raw=await r.text();try{return{json:JSON.parse(raw),raw}}catch{return{json:null,raw}}}

app.get("/",(req,res)=>res.send("Tesla TurOptimal V2.4 backend running"));
app.get("/health",(req,res)=>res.json({
  ok:true,version:"2.4",client:!!CLIENT_ID,secret:!!CLIENT_SECRET,google:!!GOOGLE_API_KEY,
  backendUrl:BACKEND_URL,appUrl:APP_URL,domain:"teslaoptimizer.netlify.app",
  endpoints:["/auth/tesla","/api/tesla-live-dashboard","/api/tesla-wake","/api/route-pro-v24"]
}));

app.get("/auth/login",(req,res)=>res.redirect("/auth/tesla"));
app.get("/api/login",(req,res)=>res.redirect("/auth/tesla"));
app.get("/auth/tesla",(req,res)=>{
 if(!CLIENT_ID)return res.status(500).send("TESLA_CLIENT_ID mangler i Railway Variables");
 const state=crypto.randomBytes(16).toString("hex"),verifier=b64(crypto.randomBytes(64)),challenge=sha256(verifier);
 pkceStore.set(state,verifier);
 const p=new URLSearchParams({client_id:CLIENT_ID,response_type:"code",redirect_uri:`${BACKEND_URL}/auth/callback`,scope:"openid offline_access vehicle_device_data vehicle_location vehicle_cmds",state,code_challenge:challenge,code_challenge_method:"S256"});
 res.redirect(`${TESLA_AUTH}/oauth2/v3/authorize?${p.toString()}`);
});
app.get("/auth/callback",async(req,res)=>{
 try{
  const {code,state}=req.query;if(!code||!state)return res.status(400).send("Mangler code/state fra Tesla. Start fra /auth/tesla.");
  const verifier=pkceStore.get(String(state));if(!verifier)return res.status(400).send("Ugyldig/utløpt state. Start på /auth/tesla igjen.");pkceStore.delete(String(state));
  const body=new URLSearchParams({grant_type:"authorization_code",client_id:CLIENT_ID,client_secret:CLIENT_SECRET,code:String(code),redirect_uri:`${BACKEND_URL}/auth/callback`,code_verifier:verifier});
  const r=await fetch(`${TESLA_AUTH}/oauth2/v3/token`,{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded",Accept:"application/json","User-Agent":"Mozilla/5.0 TeslaOptimizer/2.4"},body});
  const {json,raw}=await safeJson(r);if(!json)return res.status(500).send("Tesla svarte ikke med JSON.<br>Status: "+r.status+"<br><pre>"+raw.slice(0,1500)+"</pre>");
  if(!r.ok)return res.status(500).json({ok:false,error:"Tesla token-feil",details:json});
  savedToken={access_token:json.access_token,refresh_token:json.refresh_token,expires_at:Date.now()+(json.expires_in||3600)*1000};
  res.redirect(`${APP_URL}?tesla=connected`);
 }catch(e){res.status(500).json({ok:false,error:e.message})}
});
async function getToken(){
 if(!savedToken)throw new Error("Tesla er ikke koblet. Åpne /auth/tesla først.");
 if(Date.now()<savedToken.expires_at-120000)return savedToken.access_token;
 const body=new URLSearchParams({grant_type:"refresh_token",client_id:CLIENT_ID,client_secret:CLIENT_SECRET,refresh_token:savedToken.refresh_token});
 const r=await fetch(`${TESLA_AUTH}/oauth2/v3/token`,{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded",Accept:"application/json","User-Agent":"Mozilla/5.0 TeslaOptimizer/2.4"},body});
 const {json,raw}=await safeJson(r);if(!json)throw new Error("Tesla svarte ikke med JSON: "+raw.slice(0,800));if(!r.ok)throw new Error("Kunne ikke fornye Tesla-token: "+JSON.stringify(json));
 savedToken={access_token:json.access_token,refresh_token:json.refresh_token||savedToken.refresh_token,expires_at:Date.now()+(json.expires_in||3600)*1000};return savedToken.access_token;
}
async function teslaFetch(path,opt={}){
 const token=await getToken();
 const r=await fetch(`${TESLA_API}${path}`,{...opt,headers:{Authorization:`Bearer ${token}`,Accept:"application/json","Content-Type":"application/json",...(opt.headers||{})}});
 const {json,raw}=await safeJson(r);if(!json)throw new Error("Tesla API svarte ikke med JSON: "+raw.slice(0,800));if(!r.ok)throw new Error(JSON.stringify(json));return json;
}
async function firstVehicle(){const d=await teslaFetch("/api/1/vehicles");const v=d.response&&d.response[0];if(!v)throw new Error("Fant ingen Tesla på kontoen");return v}

app.post("/api/tesla-wake",async(req,res)=>{try{const v=await firstVehicle(),id=v.id_s||v.id,d=await teslaFetch(`/api/1/vehicles/${id}/wake_up`,{method:"POST"});res.json({ok:true,vehicle:{id,name:v.display_name||v.vehicle_name||"Tesla"},response:d.response||d})}catch(e){res.status(500).json({ok:false,error:e.message})}});
app.get("/api/tesla-live-dashboard",async(req,res)=>{
 try{
  const v=await firstVehicle(),id=v.id_s||v.id;
  const d=await teslaFetch(`/api/1/vehicles/${id}/vehicle_data?endpoints=charge_state;drive_state;vehicle_state;climate_state`);
  const r=d.response||{},c=r.charge_state||{},dr=r.drive_state||{},vs=r.vehicle_state||{},cl=r.climate_state||{};
  const tpms={fl:vs.tpms_pressure_fl??null,fr:vs.tpms_pressure_fr??null,rl:vs.tpms_pressure_rl??null,rr:vs.tpms_pressure_rr??null};
  const vals=Object.values(tpms).filter(x=>typeof x==="number");
  res.json({ok:true,connected:true,vehicle:{id,name:v.display_name||v.vehicle_name||"Tesla",state:v.state||null},telemetry:{
   batteryLevel:c.battery_level??null,usableBatteryLevel:c.usable_battery_level??null,
   idealRangeKm:c.ideal_battery_range?c.ideal_battery_range*1.60934:null,ratedRangeKm:c.battery_range?c.battery_range*1.60934:null,
   chargingState:c.charging_state??null,chargerPowerKw:c.charger_power??null,vehicleSpeedKmh:dr.speed?dr.speed*1.60934:null,
   latitude:dr.latitude??null,longitude:dr.longitude??null,shiftState:dr.shift_state??null,outsideTemp:cl.outside_temp??null,insideTemp:cl.inside_temp??null,
   tpmsAvgBar:vals.length?vals.reduce((a,b)=>a+b,0)/vals.length:null,tpms,timestamp:new Date().toISOString()
  }});
 }catch(e){res.status(500).json({ok:false,connected:false,error:e.message})}
});
app.get("/api/tesla-live",(req,res)=>{req.url="/api/tesla-live-dashboard";app._router.handle(req,res)});

function decodePolyline(str){let i=0,lat=0,lng=0,out=[];while(i<str.length){let b,s=0,r=0;do{b=str.charCodeAt(i++)-63;r|=(b&31)<<s;s+=5}while(b>=32);lat+=(r&1)?~(r>>1):(r>>1);s=0;r=0;do{b=str.charCodeAt(i++)-63;r|=(b&31)<<s;s+=5}while(b>=32);lng+=(r&1)?~(r>>1):(r>>1);out.push({lat:lat/1e5,lng:lng/1e5})}return out}
function sample(a,max=80){if(!a||a.length<=max)return a||[];let o=[];for(let i=0;i<max;i++)o.push(a[Math.round(i*(a.length-1)/(max-1))]);return o}
function hav(a,b){const R=6371,rad=x=>x*Math.PI/180,dLat=rad(b.lat-a.lat),dLon=rad(b.lng-a.lng);const x=Math.sin(dLat/2)**2+Math.cos(rad(a.lat))*Math.cos(rad(b.lat))*Math.sin(dLon/2)**2;return 2*R*Math.asin(Math.sqrt(x))}
function bear(a,b){const rad=x=>x*Math.PI/180,deg=x=>(x*180/Math.PI+360)%360;const y=Math.sin(rad(b.lng-a.lng))*Math.cos(rad(b.lat));const x=Math.cos(rad(a.lat))*Math.sin(rad(b.lat))-Math.sin(rad(a.lat))*Math.cos(rad(b.lat))*Math.cos(rad(b.lng-a.lng));return deg(Math.atan2(y,x))}
function diff(a,b){let d=Math.abs(a-b)%360;return d>180?360-d:d}
function windType(rb,wd){const d=diff(rb,wd);if(d>135)return"motvind";if(d<45)return"medvind";return"sidevind"}
function pe(h,m=1900){return h>0?(m*9.81*h)/3600000:0}
async function geocode(address){if(!GOOGLE_API_KEY)throw new Error("GOOGLE_API_KEY mangler i Railway Variables.");const url="https://maps.googleapis.com/maps/api/geocode/json?"+new URLSearchParams({address,key:GOOGLE_API_KEY});const r=await fetch(url),d=await r.json();if(d.status!=="OK"||!d.results?.[0])throw new Error("Geocoding feilet for: "+address+" ("+d.status+")");const loc=d.results[0].geometry.location;return{address,formatted:d.results[0].formatted_address,lat:loc.lat,lng:loc.lng}}
async function gRoute(points){if(!GOOGLE_API_KEY)throw new Error("GOOGLE_API_KEY mangler i Railway Variables.");const origin={location:{latLng:{latitude:points[0].lat,longitude:points[0].lng}}},destination={location:{latLng:{latitude:points.at(-1).lat,longitude:points.at(-1).lng}}},intermediates=points.slice(1,-1).map(p=>({location:{latLng:{latitude:p.lat,longitude:p.lng}}}));const body={origin,destination,intermediates,travelMode:"DRIVE",routingPreference:"TRAFFIC_UNAWARE",computeAlternativeRoutes:false,polylineQuality:"HIGH_QUALITY"};const r=await fetch("https://routes.googleapis.com/directions/v2:computeRoutes",{method:"POST",headers:{"Content-Type":"application/json","X-Goog-Api-Key":GOOGLE_API_KEY,"X-Goog-FieldMask":"routes.legs.distanceMeters,routes.legs.duration,routes.polyline.encodedPolyline"},body:JSON.stringify(body)});const d=await r.json();if(!r.ok||!d.routes?.[0])throw new Error("Google Routes feilet: "+JSON.stringify(d).slice(0,900));return d.routes[0]}
async function elev(samples){if(!GOOGLE_API_KEY)throw new Error("GOOGLE_API_KEY mangler i Railway Variables.");let all=[];for(let i=0;i<samples.length;i+=100){const chunk=samples.slice(i,i+100),locations=chunk.map(p=>`${p.lat},${p.lng}`).join("|");const url="https://maps.googleapis.com/maps/api/elevation/json?"+new URLSearchParams({locations,key:GOOGLE_API_KEY});const r=await fetch(url),d=await r.json();if(d.status!=="OK")throw new Error("Elevation API feilet: "+d.status);all.push(...d.results.map(x=>x.elevation||0))}return all}
async function meteo(lat,lng){const url="https://api.open-meteo.com/v1/forecast?"+new URLSearchParams({latitude:lat,longitude:lng,hourly:"temperature_2m,precipitation,wind_speed_10m,wind_direction_10m",forecast_days:"2",timezone:"auto"});const r=await fetch(url),d=await r.json(),i=0;return{temperature:d.hourly?.temperature_2m?.[i]??8,rain:d.hourly?.precipitation?.[i]??0,windSpeed:(d.hourly?.wind_speed_10m?.[i]??18)/3.6,windDir:d.hourly?.wind_direction_10m?.[i]??240}}
function wf(w){let extra=0,reasons=[];if(w.temperature<3){extra+=.12;reasons.push("kulde")}else if(w.temperature<8){extra+=.06;reasons.push("lav temperatur")}if(w.rain>.2){extra+=.07;reasons.push("regn/våt vei")}if(w.windType==="motvind"){extra+=.10;reasons.push("motvind")}else if(w.windType==="sidevind"){extra+=.04;reasons.push("sidevind")}else if(w.windType==="medvind"){extra-=.03;reasons.push("medvind")}return{extra,reasons}}
function tire(tesla){const t=tesla?.telemetry||{},vals=[t.tpms?.fl,t.tpms?.fr,t.tpms?.rl,t.tpms?.rr].filter(v=>typeof v==="number");if(!vals.length)return{level:"unknown",text:"Dekktrykk ikke rapportert",penalty:.02};const min=Math.min(...vals),avg=vals.reduce((a,b)=>a+b,0)/vals.length;if(min<2.6)return{level:"danger",text:"Lavt dekktrykk",penalty:.08,min,avg};if(min<2.8)return{level:"warn",text:"Litt lavt dekktrykk",penalty:.05,min,avg};if(avg<2.9)return{level:"warn",text:"Sjekk dekktrykk",penalty:.03,min,avg};return{level:"ok",text:"Dekktrykk OK",penalty:0,min,avg}}

app.post("/api/route-pro-v24",async(req,res)=>{
 try{
  const stops=(req.body.stops||[]).filter(Boolean).slice(0,20),params=req.body.params||{},tesla=req.body.tesla||{};
  if(stops.length<2)return res.status(400).json({ok:false,error:"Minst to stopp kreves"});
  const points=[];for(const s of stops)points.push(await geocode(s));
  const route=await gRoute(points),rawLegs=route.legs||[],poly=route.polyline?.encodedPolyline?decodePolyline(route.polyline.encodedPolyline):points.map(p=>({lat:p.lat,lng:p.lng}));
  const mapPoints=sample(poly,120),els=await elev(sample(poly,90));let totalUp=0,totalDown=0;for(let i=1;i<els.length;i++){const d=els[i]-els[i-1];if(d>0)totalUp+=d;else totalDown+=Math.abs(d)}
  const t=tire(tesla),batteryKwh=Number(params.batteryKwh||74),baseWhKm=Number(params.baseWhKm||155),regenEff=Number(params.regenEfficiency||65)/100,usableSoc=Number(tesla.telemetry?.usableBatteryLevel||tesla.telemetry?.batteryLevel||80);
  const mass=1750+Math.max(0,Number(params.passengers||2)-1)*80+(params.luggage==="tung"?90:params.luggage==="normal"?40:0);
  let totalKm=0,totalMinutes=0,baseKwh=0,weatherKwh=0,tireKwh=0,climbKwh=0,regenKwh=0,netKwh=0,elevationUp=0,elevationDown=0;
  const routeKm=rawLegs.reduce((s,l)=>s+((l.distanceMeters||0)/1000),0)||1,legs=[],weatherPoints=[];
  for(let i=0;i<rawLegs.length;i++){
   const a=points[i],b=points[i+1],km=(rawLegs[i].distanceMeters||hav(a,b)*1000)/1000,dur=parseInt(String(rawLegs[i].duration||"0s").replace("s",""),10)||(km/75*3600),minutes=dur/60;
   const mid={lat:(a.lat+b.lat)/2,lng:(a.lng+b.lng)/2},w0=await meteo(mid.lat,mid.lng),w={...w0,windType:windType(bear(a,b),w0.windDir)},fac=wf(w);
   const share=km/routeKm,legUp=totalUp*share,legDown=totalDown*share,legBase=km*baseWhKm/1000,legWeather=legBase*fac.extra,legTire=legBase*t.penalty,legClimb=pe(legUp,mass),legRegen=pe(legDown,mass)*regenEff,legNet=Math.max(0,legBase+legWeather+legTire+legClimb-legRegen);
   totalKm+=km;totalMinutes+=minutes;baseKwh+=legBase;weatherKwh+=legWeather;tireKwh+=legTire;climbKwh+=legClimb;regenKwh+=legRegen;netKwh+=legNet;elevationUp+=legUp;elevationDown+=legDown;
   legs.push({index:i+1,from:stops[i],to:stops[i+1],km,minutes,elevationUp:legUp,elevationDown:legDown,baseKwh:legBase,weatherKwh:legWeather,tireKwh:legTire,climbKwh:legClimb,regenKwh:legRegen,netKwh:legNet,weatherSummary:`${w.temperature.toFixed(1)}°C, ${w.windType}, vind ${w.windSpeed.toFixed(1)} m/s, regn ${w.rain.toFixed(1)} mm. ${fac.reasons.join(", ")||"normale forhold"}`,weather:w});
   const count=Math.max(1,Math.round(minutes/30));for(let p=0;p<count;p++)weatherPoints.push({timeLabel:new Date(Date.now()+(totalMinutes-minutes+p*30)*60000).toLocaleTimeString("no-NO",{hour:"2-digit",minute:"2-digit"}),place:`${stops[i]} → ${stops[i+1]}`,temperature:w.temperature,rain:w.rain,windSpeed:w.windSpeed,windType:w.windType});
  }
  const arrivalSoc=usableSoc-(netKwh/batteryKwh)*100;
  res.json({ok:true,plan:{version:"2.4",params,stops,points,mapPoints,tire:t,totalKm,totalMinutes,baseKwh,weatherKwh,tireKwh,climbKwh,regenKwh,netKwh,elevationUp,elevationDown,arrivalSoc,legs,weatherPoints}});
 }catch(e){res.status(500).json({ok:false,error:e.message})}
});
app.post("/api/route-pro-v23",(req,res)=>{req.url="/api/route-pro-v24";app._router.handle(req,res)});
app.post("/api/route-weather-v22",(req,res)=>{req.url="/api/route-pro-v24";app._router.handle(req,res)});
app.listen(PORT,()=>console.log("Tesla TurOptimal V2.4 backend running on port "+PORT));
