import express from "express";
import fetch from "node-fetch";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 8080;

const CLIENT_ID = process.env.TESLA_CLIENT_ID;
const CLIENT_SECRET = process.env.TESLA_CLIENT_SECRET;

const REDIRECT_URI =
  "https://tesla-v5-railway-backend-production.up.railway.app/auth/callback";

// -------- HEALTH --------
app.get("/health", (req, res) => {
  res.json({
    ok: true,
    teslaClientConfigured: !!CLIENT_ID && !!CLIENT_SECRET,
  });
});

// -------- LOGIN --------
app.get("/auth/tesla", (req, res) => {
  const url = `https://auth.tesla.com/oauth2/v3/authorize?client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&response_type=code&scope=openid offline_access vehicle_device_data vehicle_cmds`;

  res.redirect(url);
});

// -------- CALLBACK --------
app.get("/auth/callback", async (req, res) => {
  const code = req.query.code;

  if (!code) {
    return res.send("Mangler code fra Tesla");
  }

  try {
    const response = await fetch("https://auth.tesla.com/oauth2/v3/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        code,
        redirect_uri: REDIRECT_URI,
      }),
    });

    const data = await response.json();

    if (!response.ok) {
      return res.json({ ok: false, error: data });
    }

    res.json({
      ok: true,
      message: "Tesla login OK",
      token: data,
    });
  } catch (err) {
    res.json({ ok: false, error: err.message });
  }
});

// -------- START --------
app.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});
