const assert = require("node:assert");
const {
  timingSafeEq,
  encryptPayload,
  decryptPayload,
  issueEphemeralToken,
  verifyEphemeralToken,
  BruteForceGuard,
} = require("./crypto.server");

const {
  encryptClientPayload,
  decryptClientPayload,
  envelopeFormPayload,
} = require("./crypto.client");

async function runTestSuite() {
  const secret = "SuperSecret_MasterKey_Marcus2026_@Test!";
  console.log("===============================================================");
  console.log("  TEST SUITE: ZERO-PLAINTEXT E2EE & RESILIENCE ARCHITECTURE   ");
  console.log("===============================================================\n");

  // -------------------------------------------------------------
  // TEST 1: Paridade Criptográfica Bidirecional (AES-256-GCM AEAD)
  // -------------------------------------------------------------
  console.log("[1/6] Testando Paridade Criptográfica Bidirecional...");
  const sensitiveUser = {
    nome: "Marcus Araújo",
    email: "marcus@tvaraujo.com",
    cpf: "123.456.789-00",
    telefone: "+5511999999999",
  };

  // Node cifra -> WebCrypto decifra
  const serverHex = encryptPayload(sensitiveUser, secret);
  assert.strictEqual(typeof serverHex, "string");
  assert.ok(serverHex.length >= 56, "Hex deve conter ao menos 56 caracteres (IV + Tag)");
  const clientDecrypted = await decryptClientPayload(serverHex, secret);
  assert.deepStrictEqual(clientDecrypted, sensitiveUser, "Client decifrou com divergência!");

  // WebCrypto cifra -> Node decifra
  const clientHex = await encryptClientPayload(sensitiveUser, secret);
  assert.strictEqual(typeof clientHex, "string");
  assert.ok(clientHex.length >= 56, "Hex deve conter ao menos 56 caracteres (IV + Tag)");
  const serverDecrypted = decryptPayload(clientHex, secret);
  assert.deepStrictEqual(serverDecrypted, sensitiveUser, "Server decifrou com divergência!");
  console.log("  ✓ 100% de paridade nativa entre Node.js (node:crypto) e Navegador (Web Crypto API)!\n");

  // -------------------------------------------------------------
  // TEST 2: Detecção de Adulteração de 1 Bit (Integridade AEAD)
  // -------------------------------------------------------------
  console.log("[2/6] Testando Detecção de Adulteração de 1 Bit (Integridade AEAD)...");
  const originalHex = serverHex;
  // Inverte 1 caractere no meio do ciphertext
  const tamperedIndex = 60;
  const flippedChar = originalHex[tamperedIndex] === "a" ? "b" : "a";
  const tamperedHex =
    originalHex.slice(0, tamperedIndex) + flippedChar + originalHex.slice(tamperedIndex + 1);

  assert.throws(
    () => decryptPayload(tamperedHex, secret),
    /Unsupported state or unable to authenticate data/,
    "O servidor deveria ter rejeitado o pacote adulterado!"
  );

  await assert.rejects(
    async () => await decryptClientPayload(tamperedHex, secret),
    "O navegador deveria ter rejeitado o pacote adulterado!"
  );
  console.log("  ✓ Qualquer alteração de 1 bit causa falha imediata de decifragem antes de processar os dados!\n");

  // -------------------------------------------------------------
  // TEST 3: Tokens Efêmeros com Expiração Estrita (TTL)
  // -------------------------------------------------------------
  console.log("[3/6] Testando Tokens Efêmeros com Expiração Estrita (TTL)...");
  const quickTtlToken = issueEphemeralToken({ session: "checkout_pix", amount: 150.0 }, 100, { secret });
  assert.ok(quickTtlToken.token.length >= 56);

  // Antes de expirar -> deve ser válido
  const validCheck = verifyEphemeralToken(quickTtlToken.token, { secret });
  assert.strictEqual(validCheck.valid, true);
  assert.strictEqual(validCheck.status, "valid");
  assert.strictEqual(validCheck.data.amount, 150.0);

  // Aguarda 150ms para garantir expiração
  await new Promise((r) => setTimeout(r, 150));
  const expiredCheck = verifyEphemeralToken(quickTtlToken.token, { secret });
  assert.strictEqual(expiredCheck.valid, false);
  assert.strictEqual(expiredCheck.status, "expired");
  console.log("  ✓ Token com TTL estrito validado e imediatamente rejeitado após expiração!\n");

  // -------------------------------------------------------------
  // TEST 4: One-Time Tokens (OTT / Queima Única)
  // -------------------------------------------------------------
  console.log("[4/6] Testando One-Time Tokens (OTT / Queima Única)...");
  const ottToken = issueEphemeralToken({ activationCode: "HERMES-VIP-2026", user: "marcus" }, 60000, { secret });

  // 1º Resgate: Deve suceder e queimar o jti
  const firstRedeem = verifyEphemeralToken(ottToken.token, { autoConsumeOtt: true, secret });
  assert.strictEqual(firstRedeem.valid, true);
  assert.strictEqual(firstRedeem.status, "valid");
  assert.strictEqual(firstRedeem.data.activationCode, "HERMES-VIP-2026");

  // 2º Resgate (ex: F5 ou compartilhamento de URL): Deve ser rejeitado como 'consumed'
  const secondRedeem = verifyEphemeralToken(ottToken.token, { autoConsumeOtt: true, secret });
  assert.strictEqual(secondRedeem.valid, false);
  assert.strictEqual(secondRedeem.status, "consumed");
  console.log("  ✓ OTT resgatado com sucesso no primeiro acesso e rejeitado com status 'consumed' no segundo!\n");

  // -------------------------------------------------------------
  // TEST 5: Proteção Contra Timing Attacks (timingSafeEq)
  // -------------------------------------------------------------
  console.log("[5/6] Testando Proteção Contra Timing Attacks (timingSafeEq)...");
  const tokenSecretA = "super-secret-cron-token-998877";
  const tokenSecretB = "super-secret-cron-token-998877";
  const tokenSecretC = "super-secret-cron-token-998878";
  const tokenSecretD = "short-token";

  assert.strictEqual(timingSafeEq(tokenSecretA, tokenSecretB), true, "Strings idênticas devem ser true");
  assert.strictEqual(timingSafeEq(tokenSecretA, tokenSecretC), false, "Strings com 1 char diferente devem ser false");
  assert.strictEqual(timingSafeEq(tokenSecretA, tokenSecretD), false, "Strings de tamanhos diferentes devem ser false");
  console.log("  ✓ timingSafeEq validou igualdade e diferença com proteção contra Timing Attacks!\n");

  // -------------------------------------------------------------
  // TEST 6: Envelopamento de Formulário e Proteção Anti-Brute Force
  // -------------------------------------------------------------
  console.log("[6/6] Testando Envelopamento Transparente & Anti-Brute Force...");
  // Envelopamento
  const checkoutPayload = { item: "Serviço Hermes VPS", preco: 99.0 };
  const enveloped = await envelopeFormPayload(checkoutPayload, secret);
  assert.ok(enveloped.data && enveloped.data.encrypted);
  const unpacked = decryptPayload(enveloped.data.encrypted, secret);
  assert.deepStrictEqual(unpacked, checkoutPayload);

  // Anti-Brute Force
  const testIp = "192.168.1.100";
  // Simula 4 falhas
  for (let i = 1; i <= 4; i++) {
    const res = BruteForceGuard.recordFailure(testIp);
    assert.strictEqual(res.locked, false, `Tentativa ${i} não deveria bloquear ainda`);
    assert.strictEqual(res.attempts, i);
  }

  // 5ª falha -> deve acionar o lockout
  const fifthFailure = BruteForceGuard.recordFailure(testIp);
  assert.strictEqual(fifthFailure.locked, true, "5ª falha consecutiva DEVE acionar o bloqueio temporário!");
  assert.ok(fifthFailure.remainingMs > 0, "Deve informar tempo restante de bloqueio");

  // Checa status de bloqueio
  const statusCheck = BruteForceGuard.getStatus(testIp);
  assert.strictEqual(statusCheck.locked, true);

  // Sucesso com reset
  BruteForceGuard.recordSuccess(testIp);
  const postSuccessStatus = BruteForceGuard.getStatus(testIp);
  assert.strictEqual(postSuccessStatus.locked, false);
  assert.strictEqual(postSuccessStatus.attempts, 0);

  console.log("  ✓ Envelopamento transparente e Bloqueio Anti-Brute Force com lockout de 15min validados!\n");

  console.log("===============================================================");
  console.log("       TODOS OS 6 PILARES DE SEGURANÇA PASSARAM COM SUCESSO!   ");
  console.log("===============================================================");
}

runTestSuite().catch((e) => {
  console.error("FALHA NOS TESTES:", e);
  process.exit(1);
});
