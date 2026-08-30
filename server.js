const express = require("express");
const crypto = require("crypto");

const app = express();

app.use(express.json());

// Разрешаем запросы только с нашей GitHub Pages Mini App
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


// ========================================
// Проверка Telegram initData
// ========================================

function validateInitData(initData) {

  if (!BOT_TOKEN) {
    console.error("BOT_TOKEN отсутствует");
    return false;
  }

  if (!initData) {
    return false;
  }

  const params = new URLSearchParams(initData);


  // ----------------------------------------
  // 1. Проверяем auth_date
  // ----------------------------------------

  const authDate = Number(
    params.get("auth_date")
  );

  if (!authDate) {
    return false;
  }

  const now = Math.floor(
    Date.now() / 1000
  );


  // Максимальный возраст initData:
  // 5 минут = 300 секунд

  if (now - authDate > 300) {
    return false;
  }


  // Защита от даты из будущего

  if (authDate > now + 30) {
    return false;
  }


  // ----------------------------------------
  // 2. Получаем hash Telegram
  // ----------------------------------------

  const hash = params.get("hash");

  if (!hash) {
    return false;
  }

  params.delete("hash");


  // ----------------------------------------
  // 3. Создаём data-check-string
  // ----------------------------------------

  const dataCheckString =
    [...params.entries()]
      .sort(([a], [b]) =>
        a.localeCompare(b)
      )
      .map(
        ([key, value]) =>
          `${key}=${value}`
      )
      .join("\n");


  // ----------------------------------------
  // 4. Создаём секретный ключ
  // ----------------------------------------

  const secretKey = crypto
    .createHmac(
      "sha256",
      "WebAppData"
    )
    .update(BOT_TOKEN)
    .digest();


  // ----------------------------------------
  // 5. Вычисляем ожидаемый hash
  // ----------------------------------------

  const calculatedHash = crypto
    .createHmac(
      "sha256",
      secretKey
    )
    .update(dataCheckString)
    .digest("hex");


  // Безопасное сравнение hash

  try {

    const receivedHash =
      Buffer.from(hash, "hex");

    const expectedHash =
      Buffer.from(calculatedHash, "hex");

    if (
      receivedHash.length !==
      expectedHash.length
    ) {
      return false;
    }

    return crypto.timingSafeEqual(
      receivedHash,
      expectedHash
    );

  } catch {
    return false;
  }
}


// ========================================
// /verify
// ========================================

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
      error:
        "invalid signature or expired initData"
    });

  }


  // ----------------------------------------
  // Получаем данные пользователя
  // только ПОСЛЕ проверки подписи
  // ----------------------------------------

  const params =
    new URLSearchParams(initData);

  let user = null;

  try {

    const userData =
      params.get("user");

    if (userData) {
      user =
        JSON.parse(userData);
    }

  } catch {

    return res.status(400).json({
      ok: false,
      error: "invalid user data"
    });

  }


  // ----------------------------------------
  // Успешная проверка
  // ----------------------------------------

  return res.json({
    ok: true,
    user: user
  });

});


// ========================================
// Запуск сервера
// ========================================

const PORT =
  process.env.PORT || 3000;

app.listen(PORT, () => {

  console.log(
    "Telegram Bug Lab backend running"
  );

});

  