
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

  const dataCheckString = [...params.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}=${value}`)
    .join("\n");

  const secretKey = crypto
    .createHmac("sha256", "WebAppData")
    .update(BOT_TOKEN)
    .digest();

  const calculatedHash = crypto
    .createHmac("sha256", secretKey)
    .update(dataCheckString)
    .digest("hex");

  return calculatedHash === hash;
}

app.post("/inspect", (req, res) => {
  const { initData } = req.body;

  if (!initData) {
    return res.status(400).json({
      ok: false,
      error: "initData missing"
    });
  }

  if (!validateInitData(initData)) {
    return res.status(401).json({
      ok: false,
      error: "invalid signature"
    });
  }

  const params = new URLSearchParams(initData);

  const authDate = Number(
    params.get("auth_date")
  );

  const now = Math.floor(
    Date.now() / 1000
  );

  const ageSeconds =
    Number.isFinite(authDate)
      ? now - authDate
      : null;

  const queryId =
    params.get("query_id");

  const startParam =
    params.get("start_param");

  res.json({
    ok: true,

    auth_date: authDate || null,

    age_seconds: ageSeconds,

    query_id_present:
      Boolean(queryId),

    query_id_preview:
      queryId
        ? queryId.slice(0, 6) + "..."
        : null,

    start_param:
      startParam || null
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