

  const express = require("express");
const crypto = require("crypto");

const app = express();

app.use(express.json());

app.use((req, res, next) => {
  res.setHeader(
    "Access-Control-Allow-Origin",
    "https://rerrerrer0109-dotcom.github.io"
  );

  res.setHeader(
    "Access-Control-Allow-Methods",
    "POST, OPTIONS"
  );

  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type"
  );

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});


const BOT_TOKEN = process.env.BOT_TOKEN;


function validateInitData(initData) {

  const params = new URLSearchParams(initData);

  const hash = params.get("hash");

  if (!hash) {
    return false;
  }

  params.delete("hash");

  const dataCheckString =
    [...params.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => `${key}=${value}`)
      .join("\n");


  const secretKey =
    crypto
      .createHmac("sha256", "WebAppData")
      .update(BOT_TOKEN)
      .digest();


  const calculatedHash =
    crypto
      .createHmac("sha256", secretKey)
      .update(dataCheckString)
      .digest("hex");


  return calculatedHash === hash;
}



app.post("/verify", (req, res) => {

  const { initData } = req.body;


  if (!initData) {

    return res.status(400).json({
      ok: false,
      error: "initData missing"
    });

  }


  const valid =
    validateInitData(initData);


  if (!valid) {

    return res.status(401).json({
      ok: false,
      error: "invalid signature"
    });

  }


  const params =
    new URLSearchParams(initData);


  let user = null;

  try {

    const userData =
      params.get("user");

    if (userData) {
      user = JSON.parse(userData);
    }

  } catch {}


  const signedStartParam =
    params.get("start_param");


  res.json({

    ok: true,

    signedStartParam:
      signedStartParam || null,

    user

  });

});



app.listen(
  process.env.PORT || 3000,
  () => {
    console.log(
      "Telegram Bug Lab backend running"
    );
  }
);