// Proxy mTLS EFI Bank → expõe HTTPS simples para o Lovable chamar.
// Deploy: Render / Railway / Fly.io / VPS — qualquer um com Node 20+.
//
// Env vars necessárias:
//   EFI_CLIENT_ID, EFI_CLIENT_SECRET   — credenciais (homologação ou produção)
//   EFI_CERT_BASE64                    — certificado .p12 em base64
//   EFI_SANDBOX                        — "true" para homologação, "false" para produção
//   EFI_PIX_KEY                        — sua chave PIX cadastrada na EFI
//   PROXY_SHARED_SECRET                — segredo que o Lovable envia no header x-proxy-secret
//   EFI_WEBHOOK_HMAC                   — segredo p/ assinar callbacks repassados ao Lovable
//   LOVABLE_WEBHOOK_URL                — https://SEU-APP.lovable.app/api/public/efi-webhook
//   PORT                               — porta HTTP (Render injeta automaticamente)

import express from "express";
import https from "node:https";
import axios from "axios";
import crypto from "node:crypto";

const {
  EFI_CLIENT_ID,
  EFI_CLIENT_SECRET,
  EFI_CERT_BASE64,
  EFI_SANDBOX = "true",
  EFI_PIX_KEY,
  PROXY_SHARED_SECRET,
  EFI_WEBHOOK_HMAC = "",
  LOVABLE_WEBHOOK_URL = "",
  PORT = 3000,
} = process.env;

if (
  !EFI_CLIENT_ID ||
  !EFI_CLIENT_SECRET ||
  !EFI_CERT_BASE64 ||
  !PROXY_SHARED_SECRET
) {
  console.error("[FATAL] Variáveis obrigatórias ausentes. Veja README.md");
  process.exit(1);
}

const isSandbox = String(EFI_SANDBOX).toLowerCase() === "true";
const BASE_URL = isSandbox
  ? "https://pix-h.api.efipay.com.br"
  : "https://pix.api.efipay.com.br";

const pfx = Buffer.from(EFI_CERT_BASE64, "base64");
const httpsAgent = new https.Agent({ pfx, passphrase: "" });

const api = axios.create({
  baseURL: BASE_URL,
  httpsAgent,
  timeout: 15000,
});

// ---------- Auth (token cache) ----------
let tokenCache = { value: null, exp: 0 };
async function getToken() {
  if (tokenCache.value && Date.now() < tokenCache.exp - 30_000)
    return tokenCache.value;
  const basic = Buffer.from(`${EFI_CLIENT_ID}:${EFI_CLIENT_SECRET}`).toString(
    "base64",
  );
  const { data } = await api.post(
    "/oauth/token",
    { grant_type: "client_credentials" },
    {
      headers: {
        Authorization: `Basic ${basic}`,
        "Content-Type": "application/json",
      },
    },
  );
  tokenCache = {
    value: data.access_token,
    exp: Date.now() + (data.expires_in ?? 3600) * 1000,
  };
  return tokenCache.value;
}

// ---------- Express ----------
const app = express();
app.use(express.json({ limit: "256kb" }));

// Auth middleware (Lovable → proxy)
function requireSecret(req, res, next) {
  if (req.headers["x-proxy-secret"] !== PROXY_SHARED_SECRET) {
    return res.status(401).json({ error: "unauthorized" });
  }
  next();
}

app.get("/health", (_req, res) => res.json({ ok: true, sandbox: isSandbox }));

// POST /pix/charge  { amount: "100.00", txid?: string, description?: string, expires_in?: number }
app.post("/pix/charge", requireSecret, async (req, res) => {
  try {
    const {
      amount,
      description = "Pagamento",
      expires_in = 3600,
    } = req.body ?? {};
    if (!amount) return res.status(400).json({ error: "amount required" });
    if (!EFI_PIX_KEY)
      return res.status(500).json({ error: "EFI_PIX_KEY not set" });

    const token = await getToken();
    const payload = {
      calendario: { expiracao: Number(expires_in) },
      valor: { original: Number(amount).toFixed(2) },
      chave: EFI_PIX_KEY,
      solicitacaoPagador: String(description).slice(0, 140),
    };

    const { data: cob } = await api.post("/v2/cob", payload, {
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
    });

    // Gera QR code (imagem + copia-e-cola)
    const { data: qr } = await api.get(`/v2/loc/${cob.loc.id}/qrcode`, {
      headers: { Authorization: `Bearer ${token}` },
    });

    res.json({
      txid: cob.txid,
      status: cob.status,
      pix_copia_cola: qr.qrcode,
      qr_code_image: qr.imagemQrcode, // data:image/png;base64,...
      expires_at: new Date(
        Date.now() + Number(expires_in) * 1000,
      ).toISOString(),
      raw: cob,
    });
  } catch (e) {
    console.error("charge error", e.response?.data || e.message);
    res
      .status(500)
      .json({ error: "charge_failed", detail: e.response?.data || e.message });
  }
});

// GET /pix/status/:txid
app.get("/pix/status/:txid", requireSecret, async (req, res) => {
  try {
    const token = await getToken();
    const { data } = await api.get(`/v2/cob/${req.params.txid}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    res.json({ txid: data.txid, status: data.status, raw: data });
  } catch (e) {
    console.error("status error", e.response?.data || e.message);
    res
      .status(500)
      .json({ error: "status_failed", detail: e.response?.data || e.message });
  }
});

// Webhook EFI → este proxy → repassa assinado p/ Lovable
// Configure no painel EFI: https://SEU-PROXY/webhook/efi
app.post("/webhook/efi", express.json({ type: "*/*" }), async (req, res) => {
  try {
    if (!LOVABLE_WEBHOOK_URL) {
      console.warn("LOVABLE_WEBHOOK_URL not set, ignoring callback");
      return res.status(200).send();
    }
    const body = JSON.stringify(req.body);
    const signature = crypto
      .createHmac("sha256", EFI_WEBHOOK_HMAC)
      .update(body)
      .digest("hex");
    await axios.post(LOVABLE_WEBHOOK_URL, req.body, {
      headers: {
        "x-efi-signature": signature,
        "Content-Type": "application/json",
      },
      timeout: 10000,
    });
    res.status(200).send();
  } catch (e) {
    console.error("webhook forward error", e.message);
    res.status(200).send(); // EFI exige 200 sempre
  }
});

// Registra/atualiza a URL de webhook na EFI para a chave PIX configurada.
// Não existe botão no painel EFI; o cadastro é feito via API.
app.post("/webhook/register", requireSecret, async (req, res) => {
  try {
    if (!EFI_PIX_KEY)
      return res.status(500).json({ error: "EFI_PIX_KEY not set" });
    const token = await getToken();
    const proto = req.headers["x-forwarded-proto"] || req.protocol;
    const webhookUrl = `${proto}://${req.get("host")}/webhook/efi`;
    const { data } = await api.put(
      `/v2/webhook/${encodeURIComponent(EFI_PIX_KEY)}`,
      { webhookUrl },
      {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      },
    );
    res.json({ ok: true, webhookUrl, efi_response: data });
  } catch (e) {
    console.error("webhook register error", e.response?.data || e.message);
    res
      .status(500)
      .json({
        error: "webhook_register_failed",
        detail: e.response?.data || e.message,
      });
  }
});

app.listen(PORT, () => {
  console.log(`EFI proxy listening on :${PORT} (sandbox=${isSandbox})`);
});
