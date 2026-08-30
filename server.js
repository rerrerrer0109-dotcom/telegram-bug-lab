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

/*
  Только лабораторное хранилище.
  После перезапуска Render оно очистится.
*/
const sessions = new Map();

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

function getTelegramUser(initData) {
  if (!validateInitData(initData)) {
    return null;
  }

  const params =
    new URLSearchParams(initData);

  const rawUser =
    params.get("user");

  if (!rawUser) {
    return null;
  }

  try {
    return JSON.parse(rawUser);
  } catch {
    return null;
  }
}

function accountFingerprint(userId) {
  const value =
    crypto
      .createHash("sha256")
      .update(String(userId))
      .digest("hex");

  return value.slice(0, 12);
}

function tokenFingerprint(token) {
  return crypto
    .createHash("sha256")
    .update(token)
    .digest("hex")
    .slice(0, 12);
}


/*
  Создаём серверную лабораторную сессию,
  связанную с текущим Telegram user.id.
*/
app.post("/lab-login", (req, res) => {
  const { initData } = req.body;

  if (!initData) {
    return res.status(400).json({
      ok: false,
      error: "initData missing"
    });
  }

  const user =
    getTelegramUser(initData);

  if (!user?.id) {
    return res.status(401).json({
      ok: false,
      error: "invalid Telegram initData"
    });
  }

  const token =
    crypto.randomBytes(32).toString("hex");

  sessions.set(token, {
    telegramUserId: String(user.id),
    createdAt: Date.now()
  });

  res.json({
    ok: true,

    /*
      Сам token нужен браузеру,
      но user.id обратно не показываем.
    */
    sessionToken: token,

    telegram_account:
      accountFingerprint(user.id),

    session_fingerprint:
      tokenFingerprint(token)
  });
});


/*
  Сравниваем:

  1. кому принадлежит сохранённая session
  2. какой Telegram аккаунт открыл Mini App сейчас
*/
app.post("/lab-check", (req, res) => {
  const {
    initData,
    sessionToken
  } = req.body;

  if (!initData) {
    return res.status(400).json({
      ok: false,
      error: "initData missing"
    });
  }

  const currentUser =
    getTelegramUser(initData);

  if (!currentUser?.id) {
    return res.status(401).json({
      ok: false,
      error: "invalid Telegram initData"
    });
  }

  const currentFingerprint =
    accountFingerprint(
      currentUser.id
    );

  if (!sessionToken) {
    return res.json({
      ok: true,

      current_telegram_account:
        currentFingerprint,

      stored_session:
        false,

      comparison:
        "NO SESSION"
    });
  }

  const session =
    sessions.get(sessionToken);

  if (!session) {
    return res.json({
      ok: true,

      current_telegram_account:
        currentFingerprint,

      stored_session:
        true,

      session_valid:
        false,

      comparison:
        "SESSION NOT FOUND"
    });
  }

  const sessionFingerprint =
    accountFingerprint(
      session.telegramUserId
    );

  const sameAccount =
    String(currentUser.id) ===
    String(session.telegramUserId);

  res.json({
    ok: true,

    current_telegram_account:
      currentFingerprint,

    session_owner_account:
      sessionFingerprint,

    session_fingerprint:
      tokenFingerprint(sessionToken),

    same_account:
      sameAccount,

    comparison:
      sameAccount
        ? "MATCH"
        : "CROSS-ACCOUNT SESSION DETECTED"
  });
});


app.listen(
  process.env.PORT || 3000,
  () => {
    console.log(
      "Telegram Account Isolation Lab running"
    );
  }
);