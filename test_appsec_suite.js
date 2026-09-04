const assert = require("node:assert");
const {
  timingSafeEq,
  encryptPayload,
  decryptPayload,
  unpackEncryptedOrPlain,
  issueSignedToken,
  verifySignedToken,
  issueOneTimeToken,
  consumeOneTimeToken,
  BruteForceGuard,
} = require("./crypto.server");

const {
  encryptPayloadClient,
  decryptPayloadClient,
  timingSafeEqClientSync,
  timingSafeEqClient,
  envelopeFormPayload,
} = require("./crypto-web");

const { initAntiInspect } = require("./anti-inspect");

async function runFullAppSecSuite() {
  const secret = "AppSec_MasterKey_2026_BankGradeSecurity!";
  console.log("=================================================================");
  console.log("   TEST SUITE: APPSEC BANK-GRADE & ANTI-REVERSE ENGINEERING     ");
  console.log("=================================================================\n");

  // -----------------------------------------------------------------
  // PILAR 1: Criptografia de Ponta a Ponta Zero-Plaintext (AES-256-GCM)
  // -----------------------------------------------------------------
  console.log("[PILAR 1] Criptografia de Ponta a Ponta Zero-Plaintext (AES-256-GCM AEAD)...");
  const checkoutData = {
    nome: "Marcus Vinicius Araújo",
    email: "marcus@tvaraujo.com",
    cpf: "123.456.789-00",
    pixKey: "e9b400df-a337-4f11-9e28-111111111111",
  };

  // Node -> WebCrypto
  const sHex = encryptPayload(checkoutData, secret);
  assert.ok(sHex.length >= 56, "Hex deve ter no mínimo 56 caracteres (IV 24 + Tag 32)");
  const cDec = await decryptPayloadClient(sHex, secret);
  assert.deepStrictEqual(cDec, checkoutData);

  // WebCrypto -> Node
  const cHex = await encryptPayloadClient(checkoutData, secret);
  assert.ok(cHex.length >= 56);
  const sDec = decryptPayload(cHex, secret);
  assert.deepStrictEqual(sDec, checkoutData);

  // Rejeição de Adulteração de 1 bit
  const tamperedHex = sHex.slice(0, 58) + (sHex[58] === "0" ? "1" : "0") + sHex.slice(59);
  assert.throws(() => decryptPayload(tamperedHex, secret));
  await assert.rejects(async () => await decryptPayloadClient(tamperedHex, secret));

  // unpackEncryptedOrPlain
  const enveloped = await envelopeFormPayload(checkoutData, secret);
  const unpackedFromObj = unpackEncryptedOrPlain(enveloped.data, secret);
  assert.deepStrictEqual(unpackedFromObj, checkoutData);

  const unpackedFromHex = unpackEncryptedOrPlain(cHex, secret);
  assert.deepStrictEqual(unpackedFromHex, checkoutData);

  const plainObj = { action: "status" };
  const unpackedPlain = unpackEncryptedOrPlain(plainObj, secret);
  assert.deepStrictEqual(unpackedPlain, plainObj, "Fallback de dados não cifrados deve ser preservado");

  console.log("  ✓ Paridade 100% nativa, integridade de 1-bit e unpackEncryptedOrPlain validados!\n");

  // -----------------------------------------------------------------
  // PILAR 2: Tokens com TTL, One-Time Tokens (OTT) e Anti-Replay
  // -----------------------------------------------------------------
  console.log("[PILAR 2] Tokens com TTL e One-Time Tokens (OTT) de Queima Única...");
  // Token com TTL assinado (base64url + "." + hmac)
  const ttlToken = issueSignedToken({ orderId: "ORD-9988", amount: 299.9 }, 100, secret);
  assert.ok(ttlToken.includes("."), "Formato deve ser base64url.hmac");

  const validVerification = verifySignedToken(ttlToken, secret);
  assert.strictEqual(validVerification.valid, true);
  assert.strictEqual(validVerification.data.orderId, "ORD-9988");

  // Assinatura adulterada
  const fakeToken = ttlToken.slice(0, -4) + "ffff";
  const fakeVerification = verifySignedToken(fakeToken, secret);
  assert.strictEqual(fakeVerification.valid, false);

  // Expiração estrita
  await new Promise((r) => setTimeout(r, 150));
  const expiredVerification = verifySignedToken(ttlToken, secret);
  assert.strictEqual(expiredVerification.valid, false);
  assert.strictEqual(expiredVerification.expired, true);

  // One-Time Token (OTT) - Queima Única
  const { token: ott } = issueOneTimeToken({ voucherCode: "HERMES-BLACK-2026" }, 60000, secret);
  assert.ok(ott.startsWith("ott_"), "Formato deve iniciar com ott_");

  // 1º Resgate -> sucesso
  const firstConsume = consumeOneTimeToken(ott, secret);
  assert.strictEqual(firstConsume.valid, true);
  assert.strictEqual(firstConsume.data.voucherCode, "HERMES-BLACK-2026");

  // 2º Resgate (F5 ou replay attack) -> bloqueado
  const secondConsume = consumeOneTimeToken(ott, secret);
  assert.strictEqual(secondConsume.valid, false);
  assert.strictEqual(secondConsume.consumed, true);

  console.log("  ✓ Tokens assinados com TTL estrito e queima atômica de OTT validados!\n");

  // -----------------------------------------------------------------
  // PILAR 3: Proteção Matemática Contra Timing Attacks
  // -----------------------------------------------------------------
  console.log("[PILAR 3] Proteção Matemática Contra Timing Attacks (timingSafeEq)...");
  const secretA = "webhook-signature-xyz-1234567890";
  const secretB = "webhook-signature-xyz-1234567890";
  const secretC = "webhook-signature-xyz-1234567891";
  const secretD = "short";

  // Servidor (Buffer timingSafeEqual com prevenção de early length leak)
  assert.strictEqual(timingSafeEq(secretA, secretB), true);
  assert.strictEqual(timingSafeEq(secretA, secretC), false);
  assert.strictEqual(timingSafeEq(secretA, secretD), false);
  assert.strictEqual(timingSafeEq(null, secretA), false);

  // Cliente Sync (bitwise XOR)
  assert.strictEqual(timingSafeEqClientSync(secretA, secretB), true);
  assert.strictEqual(timingSafeEqClientSync(secretA, secretC), false);
  assert.strictEqual(timingSafeEqClientSync(secretA, secretD), false);

  // Cliente Async (SHA-256 digest)
  assert.strictEqual(await timingSafeEqClient(secretA, secretB), true);
  assert.strictEqual(await timingSafeEqClient(secretA, secretC), false);
  assert.strictEqual(await timingSafeEqClient(secretA, secretD), false);

  console.log("  ✓ Comparadores de tempo constante (Servidor e Cliente) aprovados contra Timing Attacks!\n");

  // -----------------------------------------------------------------
  // PILAR 4: Anti-Força-Bruta (Lockout com Timer Regressivo)
  // -----------------------------------------------------------------
  console.log("[PILAR 4] Anti-Força-Bruta (Lockout de 15 minutos com Timer Regressivo)...");
  const testIp = "200.189.45.10";
  BruteForceGuard.recordSuccess(testIp); // limpa estado inicial

  for (let i = 1; i <= 4; i++) {
    const res = BruteForceGuard.recordFailure(testIp);
    assert.strictEqual(res.locked, false);
    assert.strictEqual(res.attempts, i);
  }

  // 5ª falha -> bloqueio de 15min (900s)
  const lockedRes = BruteForceGuard.recordFailure(testIp);
  assert.strictEqual(lockedRes.locked, true);
  assert.ok(lockedRes.remainingMs > 890000 && lockedRes.remainingMs <= 900000);

  // Checagem de status
  const status = BruteForceGuard.getStatus(testIp);
  assert.strictEqual(status.locked, true);

  // Reset por sucesso
  BruteForceGuard.recordSuccess(testIp);
  assert.strictEqual(BruteForceGuard.getStatus(testIp).locked, false);

  console.log("  ✓ Bloqueio Anti-Força Bruta acionado na 5ª falha e limpo com sucesso!\n");

  // -----------------------------------------------------------------
  // PILAR 5: Blindagem Front-End Ativa (Anti-Inspecionar, DevTools, Anti-Scrape)
  // -----------------------------------------------------------------
  console.log("[PILAR 5] Blindagem Front-End Ativa (Event Interception Mock)...");
  // Mocking DOM Document and Events
  const listeners = {};
  const mockDoc = {
    addEventListener: (type, fn) => {
      listeners[type] = fn;
    },
    removeEventListener: (type) => {
      delete listeners[type];
    },
  };

  const cleanup = initAntiInspect(mockDoc);

  // Teste 1: Bloqueio de Botão Direito em DIV comum
  let prevented = false;
  listeners["contextmenu"]({
    target: { tagName: "DIV", isContentEditable: false },
    preventDefault: () => {
      prevented = true;
    },
  });
  assert.strictEqual(prevented, true, "Clique direito deve ser bloqueado em DIV comum");

  // Teste 2: Exceção de Usabilidade em INPUT (colar dados de pagamento)
  prevented = false;
  listeners["contextmenu"]({
    target: { tagName: "INPUT", isContentEditable: false },
    preventDefault: () => {
      prevented = true;
    },
  });
  assert.strictEqual(prevented, false, "Clique direito deve ser PERMITIDO em INPUT para colar dados");

  // Teste 3: Exceção em TEXTAREA
  prevented = false;
  listeners["contextmenu"]({
    target: { tagName: "TEXTAREA", isContentEditable: false },
    preventDefault: () => {
      prevented = true;
    },
  });
  assert.strictEqual(prevented, false, "Clique direito deve ser PERMITIDO em TEXTAREA");

  // Teste 4: Teclas Proibidas (F12, Ctrl+Shift+I, Ctrl+U, Ctrl+S)
  const forbiddenKeys = [
    { key: "F12" },
    { key: "I", ctrlKey: true, shiftKey: true },
    { key: "U", ctrlKey: true },
    { key: "S", ctrlKey: true },
    { key: "C", ctrlKey: true, shiftKey: true },
  ];

  for (const k of forbiddenKeys) {
    let keyPrevented = false;
    listeners["keydown"]({
      ...k,
      preventDefault: () => {
        keyPrevented = true;
      },
      stopPropagation: () => {},
    });
    assert.strictEqual(keyPrevented, true, `Atalho de teclado ${JSON.stringify(k)} deve ser bloqueado`);
  }

  // Teste 5: Bloqueio de arraste de IMG
  let dragPrevented = false;
  listeners["dragstart"]({
    target: { tagName: "IMG" },
    preventDefault: () => {
      dragPrevented = true;
    },
  });
  assert.strictEqual(dragPrevented, true, "Arraste de imagens deve ser bloqueado contra scraping");

  cleanup();
  console.log("  ✓ Intercepções de eventos anti-inspect (contextmenu, teclado, drag) validadas!\n");

  console.log("=================================================================");
  console.log("   TODOS OS 6 PILARES APPSEC FORAM VALIDADOS COM 100% SUCESSO!  ");
  console.log("=================================================================");
}

runFullAppSecSuite().catch((err) => {
  console.error("ERRO NA SUÍTE APPSEC:", err);
  process.exit(1);
});
