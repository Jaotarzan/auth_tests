import { Router } from "express";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import { getUserById } from "../users.js";
import { authMiddleware } from "../middlewares/auth.js";

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
    userID: user.id, // pode ser string direto
    userName: user.username,
    attestationType: "none",
  });

  // salvar challenge temporário
  challenges[userId] = options.challenge;

  res.json(options); // ⚠️ não converta challenge/id, mande cru
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
      expectedChallenge: challenges[userId],
      expectedOrigin: origin,
      expectedRPID: rpID,
    });

    if (!verification.verified) return res.status(400).send("Falha no registro");

    const { credentialID, credentialPublicKey, counter } =
      verification.registrationInfo;

    if (!user.credentials) user.credentials = [];
    user.credentials.push({
      credentialID,
      credentialPublicKey,
      counter,
      transports:
        attestationResponse.response.transports || ["internal"], // se disponível
    });

    delete challenges[userId]; // limpar challenge

    console.log("Registro bem-sucedido:", user.credentials);
    res.json({ success: true });
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
  if (!user || !user.credentials)
    return res.status(400).send("Sem credenciais");

  const options = await generateAuthenticationOptions({
    allowCredentials: user.credentials.map((c) => ({
      id: c.credentialID,
      type: "public-key",
      transports: c.transports,
    })),
    rpID,
  });

  challenges[userId] = options.challenge;

  res.json(options); // ⚠️ não altere challenge/id
});

router.post("/authn/verify/:userId", authMiddleware, async (req, res) => {
  const { userId } = req.params;
  if (req.user.id !== userId) return res.status(403).send("Acesso negado");

  const { assertionResponse } = req.body;
  const user = getUserById(userId);
  if (!user || !user.credentials)
    return res.status(400).send("Sem credenciais");

  // procurar o authenticator certo
  const authenticator = user.credentials.find((c) =>
    Buffer.from(c.credentialID).equals(
      Buffer.from(assertionResponse.id, "base64url")
    )
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

    if (!verification.verified)
      return res.status(400).send("Falha na autenticação");

    // atualizar counter do authenticator
    authenticator.counter = verification.authenticationInfo.newCounter;

    delete challenges[userId];

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).send("Erro interno");
  }
});

export default router;
