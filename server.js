const http = require("http");
const https = require("https");

// Корневой сертификат "Russian Trusted Root CA" (Минцифры России) — нужен,
// потому что platform-api2.max.ru подписан этим УЦ, а он не входит
// в стандартные глобальные доверенные хранилища.
const RUSSIAN_TRUSTED_ROOT_CA = `-----BEGIN CERTIFICATE-----
MIIFwjCCA6qgAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwcDELMAkGA1UEBhMCUlUx
PzA9BgNVBAoMNlRoZSBNaW5pc3RyeSBvZiBEaWdpdGFsIERldmVsb3BtZW50IGFu
ZCBDb21tdW5pY2F0aW9uczEgMB4GA1UEAwwXUnVzc2lhbiBUcnVzdGVkIFJvb3Qg
Q0EwHhcNMjIwMzAxMjEwNDE1WhcNMzIwMjI3MjEwNDE1WjBwMQswCQYDVQQGEwJS
VTE/MD0GA1UECgw2VGhlIE1pbmlzdHJ5IG9mIERpZ2l0YWwgRGV2ZWxvcG1lbnQg
YW5kIENvbW11bmljYXRpb25zMSAwHgYDVQQDDBdSdXNzaWFuIFRydXN0ZWQgUm9v
dCBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMfFOZ8pUAL3+r2n
qqE0Zp52selXsKGFYoG0GM5bwz1bSFtCt+AZQMhkWQheI3poZAToYJu69pHLKS6Q
XBiwBC1cvzYmUYKMYZC7jE5YhEU2bSL0mX7NaMxMDmH2/NwuOVRj8OImVa5s1F4U
zn4Kv3PFlDBjjSjXKVY9kmjUBsXQrIHeaqmUIsPIlNWUnimXS0I0abExqkbdrXbX
YwCOXhOO2pDUx3ckmJlCMUGacUTnylyQW2VsJIyIGA8V0xzdaeUXg0VZ6ZmNUr5Y
Ber/EAOLPb8NYpsAhJe2mXjMB/J9HNsoFMBFJ0lLOT/+dQvjbdRZoOT8eqJpWnVD
U+QL/qEZnz57N88OWM3rabJkRNdU/Z7x5SFIM9FrqtN8xewsiBWBI0K6XFuOBOTD
4V08o4TzJ8+Ccq5XlCUW2L48pZNCYuBDfBh7FxkB7qDgGDiaftEkZZfApRg2E+M9
G8wkNKTPLDc4wH0FDTijhgxR3Y4PiS1HL2Zhw7bD3CbslmEGgfnnZojNkJtcLeBH
BLa52/dSwNU4WWLubaYSiAmA9IUMX1/RpfpxOxd4Ykmhz97oFbUaDJFipIggx5sX
ePAlkTdWnv+RWBxlJwMQ25oEHmRguNYf4Zr/Rxr9cS93Y+mdXIZaBEE0KS2iLRqa
OiWBki9IMQU4phqPOBAaG7A+eP8PAgMBAAGjZjBkMB0GA1UdDgQWBBTh0YHlzlpf
BKrS6badZrHF+qwshzAfBgNVHSMEGDAWgBTh0YHlzlpfBKrS6badZrHF+qwshzAS
BgNVHRMBAf8ECDAGAQH/AgEEMA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQsF
AAOCAgEAALIY1wkilt/urfEVM5vKzr6utOeDWCUczmWX/RX4ljpRdgF+5fAIS4vH
tmXkqpSCOVeWUrJV9QvZn6L227ZwuE15cWi8DCDal3Ue90WgAJJZMfTshN4OI8cq
W9E4EG9wglbEtMnObHlms8F3CHmrw3k6KmUkWGoa+/ENmcVl68u/cMRl1JbW2bM+
/3A+SAg2c6iPDlehczKx2oa95QW0SkPPWGuNA/CE8CpyANIhu9XFrj3RQ3EqeRcS
AQQod1RNuHpfETLU/A2gMmvn/w/sx7TB3W5BPs6rprOA37tutPq9u6FTZOcG1Oqj
C/B7yTqgI7rbyvox7DEXoX7rIiEqyNNUguTk/u3SZ4VXE2kmxdmSh3TQvybfbnXV
4JbCZVaqiZraqc7oZMnRoWrXRG3ztbnbes/9qhRGI7PqXqeKJBztxRTEVj8ONs1d
WN5szTwaPIvhkhO3CO5ErU2rVdUr89wKpNXbBODFKRtgxUT70YpmJ46VVaqdAhOZ
D9EUUn4YaeLaS8AjSF/h7UkjOibNc4qVDiPP+rkehFWM66PVnP1Msh93tc+taIfC
EYVMxjh8zNbFuoc7fzvvrFILLe7ifvEIUqSVIC/AzplM/Jxw7buXFeGP1qVCBEHq
391d/9RAfaZ12zkwFsl+IKwE/OZxW8AHa9i1p4GO0YSNuczzEm4=
-----END CERTIFICATE-----`;

const MAX_BOT_TOKEN = process.env.MAX_BOT_TOKEN;
const MAX_CHAT_ID = process.env.MAX_CHAT_ID;
const ALLOWED_ORIGINS = new Set([
  "https://savinovplastic.ru",
  "https://www.savinovplastic.ru",
]);

const maxAgent = new https.Agent({ ca: RUSSIAN_TRUSTED_ROOT_CA });

const WINDOW_MS = 10 * 60 * 1000;
const MAX_PER_IP = 4;
const recentByIp = new Map();
const recentPhones = new Map();

function prune(now) {
  for (const [ip, times] of recentByIp) {
    const fresh = times.filter((t) => now - t < WINDOW_MS);
    if (fresh.length) recentByIp.set(ip, fresh);
    else recentByIp.delete(ip);
  }
  for (const [phone, t] of recentPhones) {
    if (now - t >= WINDOW_MS) recentPhones.delete(phone);
  }
}

function spamReason(data, origin, ip, now) {
  if (!ALLOWED_ORIGINS.has(origin)) return "origin";
  if (data.hp_x7) return "honeypot";
  // el отсутствует у тех, кому браузер показал старую версию страницы из кеша — их не режем
  if (typeof data.el === "number" && data.el < 2500) return "too_fast";
  const phone = String(data.phone || "").replace(/\D/g, "");
  if (!/^(?:7|8)\d{10}$/.test(phone) && !/^\d{10}$/.test(phone)) return "phone";
  if (new Set(phone.slice(-10)).size < 4) return "phone_junk";
  const name = String(data.name || "");
  if (name.length > 80 || /https?:|www\.|<|@|\.(ru|com|net|org|io)\b/i.test(name)) return "name";
  if (recentPhones.has(phone.slice(-10))) return "duplicate";
  if ((recentByIp.get(ip) || []).length >= MAX_PER_IP) return "rate_limit";
  return null;
}

function sendToMax(text) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ text });
    const req = https.request(
      {
        hostname: "platform-api2.max.ru",
        path: "/messages?chat_id=" + encodeURIComponent(MAX_CHAT_ID),
        method: "POST",
        agent: maxAgent,
        headers: {
          Authorization: MAX_BOT_TOKEN,
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(body),
        },
      },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => resolve({ status: res.statusCode, body: data }));
      },
    );
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

const server = http.createServer((req, res) => {
  const origin = req.headers.origin || "";
  const allowOrigin = ALLOWED_ORIGINS.has(origin) ? origin : "https://savinovplastic.ru";
  res.setHeader("Access-Control-Allow-Origin", allowOrigin);
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    return res.end();
  }
  if (req.method === "GET") {
    res.writeHead(200, { "Content-Type": "text/plain" });
    return res.end("ok");
  }
  if (req.method !== "POST") {
    res.writeHead(405);
    return res.end();
  }

  let raw = "";
  req.on("data", (c) => (raw += c));
  req.on("end", async () => {
    let data;
    try {
      data = JSON.parse(raw || "{}");
    } catch {
      res.writeHead(400, { "Content-Type": "application/json" });
      return res.end(JSON.stringify({ ok: false, error: "bad_json" }));
    }

    const now = Date.now();
    prune(now);
    const ip =
      String(req.headers["x-forwarded-for"] || "").split(",")[0].trim() ||
      req.socket.remoteAddress;
    const reason = spamReason(data, origin, ip, now);
    if (reason) {
      console.log("spam blocked:", reason, ip, JSON.stringify(data).slice(0, 300));
      res.writeHead(200, { "Content-Type": "application/json" });
      return res.end(JSON.stringify({ ok: true }));
    }
    recentByIp.set(ip, [...(recentByIp.get(ip) || []), now]);

    const text = [
      "🔔 Новая заявка с сайта savinovplastic.ru",
      "",
      "👤 Имя: " + (data.name || "—"),
      "📞 Телефон: " + (data.phone || "—"),
      data.service ? "💉 Услуга: " + data.service : null,
      data.age ? "🎂 Возраст: " + data.age : null,
      data.message ? "💬 " + data.message : null,
      "",
      "📍 " + (data.source === "modal" ? "Модальное окно" : "Форма на сайте"),
    ]
      .filter(Boolean)
      .join("\n");

    try {
      const result = await sendToMax(text);
      const ok = result.status >= 200 && result.status < 300;
      if (ok) recentPhones.set(String(data.phone).replace(/\D/g, "").slice(-10), now);
      res.writeHead(ok ? 200 : 502, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok, result: result.body }));
    } catch (err) {
      res.writeHead(502, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: false, error: String(err) }));
    }
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log("MAX relay listening on " + PORT));
