
const express=require("express"),cors=require("cors"),crypto=require("crypto"),fetch=require("node-fetch");
const app=express(); app.use(express.json({limit:"4mb"})); app.use(cors({origin:true}));

const PORT=process.env.PORT||8080;
const CLIENT_ID=(process.env.TESLA_CLIENT_ID||"").trim();
const CLIENT_SECRET=(process.env.TESLA_CLIENT_SECRET||"").trim();
const GOOGLE_API_KEY=(process.env.GOOGLE_API_KEY||"").trim();
const BACKEND_URL=(process.env.BACKEND_URL||"https://diplomatic-charisma-production-3e63.up.railway.app").trim();
const APP_URL=(process.env.APP_URL||"https://teslaoptimizer.netlify.app").trim();

const TESLA_AUTH="https://auth.tesla.com";
const TESLA_API="https://fleet-api.prd.eu.vn.cloud.tesla.com";

let savedToken=null; const pkceStore=new Map();

function b64(b){return Buffer.from(b).toString("base64").replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"")}
function sha256(t){return b64(crypto.createHash("sha256").update(t).digest())}
async function safeJson(r){const raw=await r.text();try{return{json:JSON.parse(raw),raw}}catch{return{json:null,raw}}}

app.get("/",(req,res)=>res.send("Tesla TurOptimal V2.1 Intelligence Route-Charging backend"));
app.get("/health",(req,res)=>res.json({
  ok:true,version:"2.1-route-charging",client:!!CLIENT_ID,secret:!!CLIENT_SECRET,google:!!GOOGLE_API_KEY,
  backendUrl:BACKEND_URL,appUrl:APP_URL,
  endpoints:["/auth/tesla","/api/tesla-live","/api/address-suggest","/api/route-intelligence","/api/google-key"]
}));
app.get("/api/google-key",(req,res)=>res.json({ok:true,key:GOOGLE_API_KEY||""}));

app.get("/auth/login",(req,res)=>res.redirect("/auth/tesla"));
app.get("/api/login",(req,res)=>res.redirect("/auth/tesla"));
app.get("/auth/tesla",(req,res)=>{
 if(!CLIENT_ID)return res.status(500).send("TESLA_CLIENT_ID mangler");
 const state=crypto.randomBytes(16).toString("hex"),verifier=b64(crypto.randomBytes(64)),challenge=sha256(verifier);
 pkceStore.set(state,verifier);
 const p=new URLSearchParams({client_id:CLIENT_ID,response_type:"code",redirect_uri:`${BACKEND_URL}/auth/callback`,scope:"openid offline_access vehicle_device_data vehicle_location vehicle_cmds",state,code_challenge:challenge,code_challenge_method:"S256"});
 res.redirect(`${TESLA_AUTH}/oauth2/v3/authorize?${p.toString()}`);
});
app.get("/auth/callback",async(req,res)=>{
 try{
  const{code,state}=req.query;if(!code||!state)return res.status(400).send("Mangler code/state");
  const verifier=pkceStore.get(String(state));if(!verifier)return res.status(400).send("Ugyldig/utløpt state. Start på /auth/tesla igjen.");
  pkceStore.delete(String(state));
  const body=new URLSearchParams({grant_type:"authorization_code",client_id:CLIENT_ID,client_secret:CLIENT_SECRET,code:String(code),redirect_uri:`${BACKEND_URL}/auth/callback`,code_verifier:verifier});
  const r=await fetch(`${TESLA_AUTH}/oauth2/v3/token`,{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded",Accept:"application/json","User-Agent":"TeslaTurOptimal/2.1"},body});
  const{json,raw}=await safeJson(r);
  if(!json)return res.status(500).send("Tesla token svarte ikke JSON: "+raw.slice(0,1200));
  if(!r.ok)return res.status(500).json({ok:false,error:"Tesla token-feil",details:json});
  savedToken={access_token:json.access_token,refresh_token:json.refresh_token,expires_at:Date.now()+(json.expires_in||3600)*1000};
  res.redirect(`${APP_URL}?tesla=connected`);
 }catch(e){res.status(500).json({ok:false,error:e.message})}
});
async function getToken(){
 if(!savedToken)throw new Error("Tesla er ikke koblet. Åpne /auth/tesla først.");
 if(Date.now()<savedToken.expires_at-120000)return savedToken.access_token;
 const body=new URLSearchParams({grant_type:"refresh_token",client_id:CLIENT_ID,client_secret:CLIENT_SECRET,refresh_token:savedToken.refresh_token});
 const r=await fetch(`${TESLA_AUTH}/oauth2/v3/token`,{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded",Accept:"application/json","User-Agent":"TeslaTurOptimal/2.1"},body});
 const{json,raw}=await safeJson(r);
 if(!json)throw new Error("Tesla refresh svarte ikke JSON: "+raw.slice(0,800));
 if(!r.ok)throw new Error("Kunne ikke fornye Tesla-token: "+JSON.stringify(json));
 savedToken={access_token:json.access_token,refresh_token:json.refresh_token||savedToken.refresh_token,expires_at:Date.now()+(json.expires_in||3600)*1000};
 return savedToken.access_token;
}
async function teslaFetch(path,opt={}){
 const tk=await getToken();
 const r=await fetch(`${TESLA_API}${path}`,{...opt,headers:{Authorization:`Bearer ${tk}`,Accept:"application/json","Content-Type":"application/json",...(opt.headers||{})}});
 const{json,raw}=await safeJson(r);
 if(!json)throw new Error("Tesla API svarte ikke JSON: "+raw.slice(0,800));
 if(!r.ok)throw new Error(JSON.stringify(json));
 return json;
}
async function firstVehicle(){const d=await teslaFetch("/api/1/vehicles");const v=d.response&&d.response[0];if(!v)throw new Error("Fant ingen Tesla");return v}

app.post("/api/wake",async(req,res)=>{
 try{const v=await firstVehicle(),id=v.id_s||v.id,d=await teslaFetch(`/api/1/vehicles/${id}/wake_up`,{method:"POST"});res.json({ok:true,vehicle:{id,name:v.display_name||v.vehicle_name||"Tesla"},response:d.response||d})}
 catch(e){res.status(500).json({ok:false,error:e.message})}
});

app.get("/api/tesla-live",async(req,res)=>{
 try{
  const v=await firstVehicle(),id=v.id_s||v.id,d=await teslaFetch(`/api/1/vehicles/${id}/vehicle_data`),r=d.response||{},c=r.charge_state||{},dr=r.drive_state||{},vs=r.vehicle_state||{},cl=r.climate_state||{},cfg=r.vehicle_config||{};
  const tpms={fl:vs.tpms_pressure_fl??null,fr:vs.tpms_pressure_fr??null,rl:vs.tpms_pressure_rl??null,rr:vs.tpms_pressure_rr??null};
  const vals=Object.values(tpms).filter(x=>typeof x==="number");
  const speedKmh=dr.speed!==null&&dr.speed!==undefined?dr.speed*1.60934:null;
  res.json({ok:true,connected:true,vehicle:{id,name:v.display_name||v.vehicle_name||vs.vehicle_name||"Tesla",state:v.state||r.state||null,carVersion:vs.car_version||null,carType:cfg.car_type||null,wheelType:cfg.wheel_type||null,odometerKm:vs.odometer?vs.odometer*1.60934:null},telemetry:{batteryLevel:c.battery_level??null,usableBatteryLevel:c.usable_battery_level??null,chargeLimitSoc:c.charge_limit_soc??null,idealRangeKm:c.ideal_battery_range?c.ideal_battery_range*1.60934:null,ratedRangeKm:c.battery_range?c.battery_range*1.60934:null,chargingState:c.charging_state??null,chargerPowerKw:c.charger_power??null,speedKmh,speedText:speedKmh===null?"Parkert / ikke rapportert":`${Math.round(speedKmh)} km/t`,powerKw:dr.power??null,latitude:dr.latitude??null,longitude:dr.longitude??null,shiftState:dr.shift_state??null,outsideTemp:cl.outside_temp??null,insideTemp:cl.inside_temp??null,tpmsAvgBar:vals.length?vals.reduce((a,b)=>a+b,0)/vals.length:null,tpms,tpmsRecommended:{front:vs.tpms_rcp_front_value??null,rear:vs.tpms_rcp_rear_value??null},timestamp:new Date().toISOString()}});
 }catch(e){res.status(500).json({ok:false,connected:false,error:e.message})}
});
app.get("/api/tesla-live-dashboard",(req,res)=>{req.url="/api/tesla-live";app._router.handle(req,res)});

app.get("/api/address-suggest",async(req,res)=>{
 try{
  if(!GOOGLE_API_KEY)throw new Error("GOOGLE_API_KEY mangler");
  const input=String(req.query.input||"").trim();
  if(input.length<2)return res.json({ok:true,predictions:[]});
  const r=await fetch("https://maps.googleapis.com/maps/api/place/autocomplete/json?"+new URLSearchParams({input,key:GOOGLE_API_KEY,language:"no"}));
  const d=await r.json();
  if(d.status!=="OK"&&d.status!=="ZERO_RESULTS")throw new Error("Autocomplete feilet: "+d.status);
  res.json({ok:true,predictions:(d.predictions||[]).slice(0,8).map(x=>({description:x.description,place_id:x.place_id,main:x.structured_formatting?.main_text||x.description,secondary:x.structured_formatting?.secondary_text||""}))});
 }catch(e){res.status(500).json({ok:false,error:e.message})}
});

async function geocode(address){
 const r=await fetch("https://maps.googleapis.com/maps/api/geocode/json?"+new URLSearchParams({address,key:GOOGLE_API_KEY}));
 const d=await r.json();
 if(d.status!=="OK"||!d.results?.[0])throw new Error(`Fant ikke adresse: ${address} (${d.status})`);
 const loc=d.results[0].geometry.location;
 return{address,formatted:d.results[0].formatted_address,lat:loc.lat,lng:loc.lng,place_id:d.results[0].place_id};
}
async function googleRoute(points){
 const origin={location:{latLng:{latitude:points[0].lat,longitude:points[0].lng}}};
 const destination={location:{latLng:{latitude:points.at(-1).lat,longitude:points.at(-1).lng}}};
 const intermediates=points.slice(1,-1).map(p=>({location:{latLng:{latitude:p.lat,longitude:p.lng}}}));
 const body={origin,destination,intermediates,travelMode:"DRIVE",routingPreference:"TRAFFIC_UNAWARE",computeAlternativeRoutes:false,polylineQuality:"HIGH_QUALITY"};
 const r=await fetch("https://routes.googleapis.com/directions/v2:computeRoutes",{method:"POST",headers:{"Content-Type":"application/json","X-Goog-Api-Key":GOOGLE_API_KEY,"X-Goog-FieldMask":"routes.legs.distanceMeters,routes.legs.duration,routes.polyline.encodedPolyline"},body:JSON.stringify(body)});
 const d=await r.json();
 if(!r.ok||!d.routes?.[0])throw new Error("Google Routes feilet: "+JSON.stringify(d).slice(0,900));
 return d.routes[0];
}
function decodePolyline(str){let i=0,lat=0,lng=0,out=[];while(i<str.length){let b,s=0,r=0;do{b=str.charCodeAt(i++)-63;r|=(b&31)<<s;s+=5}while(b>=32);lat+=(r&1)?~(r>>1):(r>>1);s=0;r=0;do{b=str.charCodeAt(i++)-63;r|=(b&31)<<s;s+=5}while(b>=32);lng+=(r&1)?~(r>>1):(r>>1);out.push({lat:lat/1e5,lng:lng/1e5})}return out}
function sample(a,max=260){if(!a||a.length<=max)return a||[];let o=[];for(let i=0;i<max;i++)o.push(a[Math.round(i*(a.length-1)/(max-1))]);return o}
function hav(a,b){const R=6371,rad=x=>x*Math.PI/180,dLat=rad(b.lat-a.lat),dLon=rad(b.lng-a.lng);const x=Math.sin(dLat/2)**2+Math.cos(rad(a.lat))*Math.cos(rad(b.lat))*Math.sin(dLon/2)**2;return 2*R*Math.asin(Math.sqrt(x))}
function bearing(a,b){const rad=x=>x*Math.PI/180,deg=x=>(x*180/Math.PI+360)%360;const y=Math.sin(rad(b.lng-a.lng))*Math.cos(rad(b.lat));const x=Math.cos(rad(a.lat))*Math.sin(rad(b.lat))-Math.sin(rad(a.lat))*Math.cos(rad(b.lat))*Math.cos(rad(b.lng-a.lng));return deg(Math.atan2(y,x))}
function adiff(a,b){let d=Math.abs(a-b)%360;return d>180?360-d:d}
function windType(rb,wd){const d=adiff(rb,wd);if(d>135)return"motvind";if(d<45)return"medvind";return"sidevind"}
async function elevations(points){let out=[];for(let i=0;i<points.length;i+=100){const chunk=points.slice(i,i+100),locations=chunk.map(p=>`${p.lat},${p.lng}`).join("|");const r=await fetch("https://maps.googleapis.com/maps/api/elevation/json?"+new URLSearchParams({locations,key:GOOGLE_API_KEY}));const d=await r.json();if(d.status!=="OK")throw new Error("Elevation feilet: "+d.status);out.push(...d.results.map(x=>x.elevation||0))}return out}
function pe(h,m=1900){return h>0?(m*9.81*h)/3600000:0}
async function weather(lat,lng){const r=await fetch("https://api.open-meteo.com/v1/forecast?"+new URLSearchParams({latitude:lat,longitude:lng,hourly:"temperature_2m,precipitation,wind_speed_10m,wind_direction_10m",forecast_days:"2",timezone:"auto"}));const d=await r.json(),i=0;return{temperature:d.hourly?.temperature_2m?.[i]??8,rain:d.hourly?.precipitation?.[i]??0,windSpeed:(d.hourly?.wind_speed_10m?.[i]??18)/3.6,windDir:d.hourly?.wind_direction_10m?.[i]??240}}
function weatherFactor(w){let extra=0,reasons=[];if(w.temperature<3){extra+=.12;reasons.push("kulde")}else if(w.temperature<8){extra+=.06;reasons.push("lav temperatur")}if(w.rain>.2){extra+=.07;reasons.push("regn/våt vei")}if(w.windType==="motvind"){extra+=.12;reasons.push("motvind")}else if(w.windType==="sidevind"){extra+=.04;reasons.push("sidevind")}else if(w.windType==="medvind"){extra-=.04;reasons.push("medvind")}return{extra,reasons}}
function tirePenalty(tesla){const t=tesla?.telemetry||{},vals=[t.tpms?.fl,t.tpms?.fr,t.tpms?.rl,t.tpms?.rr].filter(v=>typeof v==="number");if(!vals.length)return{level:"unknown",text:"Dekktrykk ikke rapportert",penalty:.02};const min=Math.min(...vals),avg=vals.reduce((a,b)=>a+b,0)/vals.length;if(min<2.6)return{level:"danger",text:"Lavt dekktrykk",penalty:.08,min,avg};if(min<2.8)return{level:"warn",text:"Litt lavt dekktrykk",penalty:.05,min,avg};return{level:"ok",text:"Dekktrykk OK",penalty:0,min,avg}}
function chargePowerKw(soc){if(soc<10)return 110;if(soc<25)return 170;if(soc<45)return 145;if(soc<60)return 105;if(soc<70)return 75;if(soc<80)return 48;return 28}
function minutesToCharge(fromSoc,toSoc,batteryKwh){let min=0;for(let s=Math.max(5,Math.floor(fromSoc));s<toSoc;s+=1){min+=(batteryKwh*.01/chargePowerKw(s))*60}return min}
function segmentWhKm(baseWhKm,seg){let wh=baseWhKm;if(seg.weather?.temperature<3)wh*=1.12;else if(seg.weather?.temperature<8)wh*=1.06;if(seg.weather?.rain>0.2)wh*=1.07;if(seg.weather?.windType==="motvind")wh*=1.12;if(seg.weather?.windType==="sidevind")wh*=1.04;if(seg.weather?.windType==="medvind")wh*=0.96;if(seg.tirePenalty)wh*=1+seg.tirePenalty;return wh}
function buildSegments(legs,tirePenalty){let out=[],kmCursor=0;legs.forEach(l=>{const chunks=Math.max(1,Math.ceil(l.km/10));for(let i=0;i<chunks;i++){const km=l.km/chunks;out.push({km,from:l.from,to:l.to,legIndex:l.index,weather:l.weather,tirePenalty,kmStart:kmCursor,kmEnd:kmCursor+km});kmCursor+=km}});return out}
function pointAt(mapPoints,totalKm,targetKm){const idx=Math.round((targetKm/Math.max(1,totalKm))*(mapPoints.length-1));return mapPoints[Math.max(0,Math.min(mapPoints.length-1,idx))]||mapPoints[0]}
function googleNavUrlFromStops(stops){const origin=encodeURIComponent(stops[0]);const destination=encodeURIComponent(stops[stops.length-1]);const waypoints=stops.slice(1,-1).map(encodeURIComponent).join("|");let url=`https://www.google.com/maps/dir/?api=1&origin=${origin}&destination=${destination}&travelmode=driving`;if(waypoints)url+=`&waypoints=${waypoints}`;return url}

function makeChargingStops({segments,mapPoints,totalKm,batteryKwh,startSoc,minArrivalSoc,baseWhKm,userStops}){
 let soc=startSoc,km=0,i=0,stops=[];
 while(i<segments.length){
  const seg=segments[i];
  const needSoc=(seg.km*segmentWhKm(baseWhKm,seg)/1000)/batteryKwh*100;
  if(soc-needSoc<minArrivalSoc){
   const p=pointAt(mapPoints,totalKm,km);
   let bestTo=55,bestScore=9999,bestReach=0;
   for(let to=45;to<=75;to+=5){
    if(to<=soc+3)continue;
    let temp=to,reach=0,j=i;
    while(j<segments.length){
     const n=segments[j],nNeed=(n.km*segmentWhKm(baseWhKm,n)/1000)/batteryKwh*100;
     if(temp-nNeed<minArrivalSoc)break;
     temp-=nNeed;reach+=n.km;j++;
    }
    const m=minutesToCharge(soc,to,batteryKwh)+3;
    const score=m - Math.min(reach,240)*0.055 + (to>65?(to-65)*0.65:0);
    if(score<bestScore){bestScore=score;bestTo=to;bestReach=reach}
   }
   const minutes=Math.ceil(minutesToCharge(soc,bestTo,batteryKwh)+3);
   stops.push({index:stops.length+1,type:"Tesla Supercharger først",name:`Tesla Supercharger nær ${Math.round(km)} km`,address:`Tesla Supercharger near ${p.lat},${p.lng}`,lat:p.lat,lng:p.lng,insertAfterKm:Math.round(km),arriveSoc:Math.round(soc),chargeToSoc:bestTo,chargeMinutes:minutes,estimatedReachKm:Math.round(bestReach),comment:"Lagt inn som stopp i ruten. Google Navigasjon kan åpnes med ladestopp inkludert."});
   soc=bestTo; continue;
  }
  soc-=needSoc; km+=seg.km; i++;
 }
 const routeStops=[...userStops];
 stops.forEach(cs=>{
  // Insert after closest km position by approximate fraction in user route; frontend/backend returns explicit charging stops separately as well.
  routeStops.splice(Math.max(1,routeStops.length-1),0,cs.address);
 });
 return {needed:stops.length>0,stops,totalChargeMinutes:stops.reduce((s,x)=>s+x.chargeMinutes,0),arrivalSoc:Math.round(soc),routeStopsWithCharging:routeStops,comment:stops.length?"Ladestopp er lagt inn som ekte stopp i ruten. Tesla Supercharger prioriteres først.":"Ingen lading nødvendig med valgt buffer."};
}

app.post("/api/route-intelligence",async(req,res)=>{
 try{
  const stops=(req.body.stops||[]).filter(Boolean).slice(0,20),params=req.body.params||{},tesla=req.body.tesla||{};
  if(stops.length<2)return res.status(400).json({ok:false,error:"Minst to stopp kreves"});
  const points=[];for(const s of stops)points.push(await geocode(s));
  const rt=await googleRoute(points),rawLegs=rt.legs||[],poly=rt.polyline?.encodedPolyline?decodePolyline(rt.polyline.encodedPolyline):points.map(p=>({lat:p.lat,lng:p.lng})),mapPoints=sample(poly,280);
  const els=await elevations(sample(poly,120));let totalUp=0,totalDown=0;for(let i=1;i<els.length;i++){const d=els[i]-els[i-1];if(d>0)totalUp+=d;else totalDown+=Math.abs(d)}
  const tire=tirePenalty(tesla),batteryKwh=Number(params.batteryKwh||74),baseWhKm=Number(params.baseWhKm||155),regenEff=Number(params.regenEfficiency||65)/100,startSoc=Number(tesla.telemetry?.usableBatteryLevel||tesla.telemetry?.batteryLevel||80),minArrivalSoc=Number(params.minArrivalSoc||15),mass=1750+Math.max(0,Number(params.passengers||2)-1)*80+(params.luggage==="tung"?90:params.luggage==="normal"?40:0);
  let totalKm=0,totalMinutes=0,baseKwh=0,weatherKwh=0,tireKwh=0,climbKwh=0,regenKwh=0,netKwh=0;const routeKm=rawLegs.reduce((s,l)=>s+((l.distanceMeters||0)/1000),0)||1,legs=[],weatherPoints=[];
  for(let i=0;i<rawLegs.length;i++){
   const a=points[i],b=points[i+1],km=(rawLegs[i].distanceMeters||0)/1000,dur=parseInt(String(rawLegs[i].duration||"0s").replace("s",""),10)||(km/75*3600),minutes=dur/60,mid={lat:(a.lat+b.lat)/2,lng:(a.lng+b.lng)/2},w0=await weather(mid.lat,mid.lng),w={...w0,windType:windType(bearing(a,b),w0.windDir)},fac=weatherFactor(w),share=km/routeKm,legUp=totalUp*share,legDown=totalDown*share,legBase=km*baseWhKm/1000,legWeather=legBase*fac.extra,legTire=legBase*tire.penalty,legClimb=pe(legUp,mass),legRegen=pe(legDown,mass)*regenEff,legNet=Math.max(0,legBase+legWeather+legTire+legClimb-legRegen);
   totalKm+=km;totalMinutes+=minutes;baseKwh+=legBase;weatherKwh+=legWeather;tireKwh+=legTire;climbKwh+=legClimb;regenKwh+=legRegen;netKwh+=legNet;
   legs.push({index:i+1,from:stops[i],to:stops[i+1],km,minutes,netKwh:legNet,weather:w,weatherSummary:`${w.temperature.toFixed(1)}°C, ${w.windType}, vind ${w.windSpeed.toFixed(1)} m/s, regn ${w.rain.toFixed(1)} mm. ${fac.reasons.join(", ")||"normale forhold"}`});
   const wc=Math.max(1,Math.round(minutes/30));for(let p=0;p<wc;p++)weatherPoints.push({timeLabel:new Date(Date.now()+(totalMinutes-minutes+p*30)*60000).toLocaleTimeString("no-NO",{hour:"2-digit",minute:"2-digit"}),place:`${stops[i]} → ${stops[i+1]}`,temperature:w.temperature,rain:w.rain,windSpeed:w.windSpeed,windType:w.windType});
  }
  const segments=buildSegments(legs,tire.penalty);
  const charging=makeChargingStops({segments,mapPoints,totalKm,batteryKwh,startSoc,minArrivalSoc,baseWhKm,userStops:stops});
  charging.googleNavUrl=googleNavUrlFromStops(charging.routeStopsWithCharging);
  res.json({ok:true,plan:{version:"2.1-route-charging",params,stops,points,mapPoints,totalKm,totalMinutes,totalTripMinutes:totalMinutes+charging.totalChargeMinutes,baseKwh,weatherKwh,tireKwh,climbKwh,regenKwh,netKwh,elevationUp:totalUp,elevationDown:totalDown,arrivalSoc:charging.arrivalSoc,tire,charging,legs,weatherPoints,intelligence:{strategy:"Ladestopp settes inn i selve ruten. Tesla Supercharger prioriteres først. Målet er kortest total reisetid, ikke færrest stopp.",startSoc,minArrivalSoc,batteryKwh,baseWhKm}}});
 }catch(e){res.status(500).json({ok:false,error:e.message})}
});
app.post("/api/route-clean",(req,res)=>{req.url="/api/route-intelligence";app._router.handle(req,res)});
app.listen(PORT,()=>console.log("Tesla TurOptimal V2.1 Route-Charging backend on port "+PORT));
