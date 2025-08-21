import { Router } from "express";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import { getUserById } from "../users.js";
import { authMiddleware } from "../middlewares/auth.js";
import base64url from "base64url";
import { Buffer } from "buffer";

const router = Router();
const rpID = "eusoulindo.local";
const origin = `https://${rpID}:5173`;

// Temporário: salvar challenges em memória
const challenges = {}; // { [userId]: challenge }

// -----------------------
// Registro WebAuthn
// -----------------------
router.get("/register/options/:userId", authMiddleware, async (req, res) => {
  const { userId } = req.params;
  if (req.user.id !== userId) return res.status(403).send("Acesso negado");

  const user = getUserById(userId);
  if (!user) return res.status(404).send("Usuário não encontrado");

  const options = await generateRegistrationOptions({
    rpName: "Meu App",
    rpID,
    userID: Buffer.from(user.id, "utf8"), // agora Buffer
    userName: user.username,
  });

const challenge = base64url.encode(options.challenge);

  // Salvar challenge para verificação posterior
  challenges[userId] = challenge;

  // Converter challenge e user.id para base64url
  options.challenge = challenge;
  options.user.id = base64url.encode(options.user.id);

  res.json(options);
});

router.post("/register/verify/:userId", authMiddleware, async (req, res) => {
  const { userId } = req.params;
  if (req.user.id !== userId) return res.status(403).send("Acesso negado");

  const { attestationResponse } = req.body;
  const user = getUserById(userId);
  if (!user) return res.status(404).send("Usuário não encontrado");

  try {
    const verification = await verifyRegistrationResponse({
      response: attestationResponse,
      expectedChallenge: challenges[userId], // usar challenge salvo
      expectedOrigin: origin,
      expectedRPID: rpID,
    });

    if (!verification.verified) return res.status(400).send("Falha no registro");

    if (!user.credentials) user.credentials = [];
    user.credentials.push(verification.registrationInfo);

    // remover challenge após uso
    delete challenges[userId];

    console.log("Registro bem-sucedido:", user.credentials);
    res.json({ success: true, message: `Registro bem-sucedido para ${user.credentials}` });
  } catch (err) {
    console.error(err);
    res.status(500).send("Erro interno");
  }
});

// -----------------------
// Autenticação WebAuthn
// -----------------------
router.get("/authn/options/:userId", authMiddleware, async (req, res) => {
  const { userId } = req.params;
  if (req.user.id !== userId) return res.status(403).send("Acesso negado");

  const user = getUserById(userId);
  if (!user || !user.credentials) return res.status(400).send("Sem credenciais");

  const options = await generateAuthenticationOptions({
    allowCredentials: user.credentials.map(c => ({
      id: Buffer.isBuffer(c.credentialID)
        ? c.credentialID
        : Buffer.from(c.credentialID, "base64url"), // converte string para Buffer
      type: "public-key",
      transports: c.transports || ["internal"],
    })),
    rpID,
  });

  // salvar challenge em memória (não mexe no objeto enviado ao cliente)
  challenges[userId] = options.challenge;

  console.log(`\n[AUTH OPTIONS] userId: ${userId}`);
  console.log("Challenges salvos:", challenges[userId]);
  console.log(
    "AllowCredentials:",
    user.credentials.map(c => ({
      credentialID: c.credentialID,
      transports: c.transports || ["internal"],
    }))
  );

  res.json(options); // envia cru, sem base64url
});

router.post("/authn/verify/:userId", authMiddleware, async (req, res) => {
  const { userId } = req.params;
  if (req.user.id !== userId) return res.status(403).send("Acesso negado");

  const { assertionResponse } = req.body;
  const user = getUserById(userId);
  if (!user || !user.credentials) return res.status(400).send("Sem credenciais");

  console.log(`\n[AUTH VERIFY] userId: ${userId}`);
  console.log("Received assertionResponse.id:", assertionResponse.id);
  console.log("Expected challenge:", challenges[userId]);

  // localizar o autenticador pelo credentialID
  const authenticator = user.credentials.find(c =>
    Buffer.from(c.credentialID, "base64url").equals(
      Buffer.from(assertionResponse.id, "base64url")
    )
  );

  console.log(
    "Matching authenticator:",
    authenticator ? authenticator.credentialID : null
  );

  if (!authenticator) return res.status(400).send("Credencial não encontrada");

  try {
    const verification = await verifyAuthenticationResponse({
      response: assertionResponse,
      expectedChallenge: challenges[userId],
      expectedOrigin: origin,
      expectedRPID: rpID,
      authenticator,
    });

    console.log("Verification result:", verification);

    if (!verification.verified) return res.status(400).send("Falha na autenticação");

    // remover challenge após verificação
    delete challenges[userId];

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).send("Erro interno");
  }
});

export default router;
