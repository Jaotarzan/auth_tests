import { Router } from "express";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} from "@simplewebauthn/server";
import { getAllUsers, getUserById } from "../users.js";
import { authMiddleware } from "../middlewares/auth.js";

const router = Router();
const rpID = "eusoulindo.local";
const origin = `https://${rpID}:5173`;

// ========================
// Registro de WebAuthn
// ========================

// Gerar opções de registro
router.get("/register/options/:userId", authMiddleware, async (req, res) => {
  const { userId } = req.params;

  // Confere se o usuário logado está requisitando suas próprias credenciais
  if (req.user.id !== userId) return res.status(403).send("Acesso negado");

  const user = getUserById(userId);
  if (!user) return res.status(404).send("Usuário não encontrado");

  const options = generateRegistrationOptions({
    rpName: "Meu App",
    rpID,
    userID: Buffer.from(user.id, "utf8"),
    userName: user.username,
  });

  res.json({ ...options, challenge: options.challenge });
});

// Verificar registro
router.post("/register/verify/:userId", authMiddleware, async (req, res) => {
  const { userId } = req.params;
  if (req.user.id !== userId) return res.status(403).send("Acesso negado");

  const { attestationResponse } = req.body;
  const user = getUserById(userId);
  if (!user) return res.status(404).send("Usuário não encontrado");

  try {
    const verification = await verifyRegistrationResponse({
      response: attestationResponse,
      expectedChallenge: attestationResponse.response.clientDataJSON.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
    });

    if (!verification.verified) return res.status(400).send("Falha no registro");

    if (!user.credentials) user.credentials = [];
    user.credentials.push(verification.registrationInfo);

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).send("Erro interno");
  }
});

// ========================
// Autenticação de WebAuthn
// ========================

// Gerar opções de autenticação
router.get("/authn/options/:userId", authMiddleware, async (req, res) => {
  const { userId } = req.params;
  if (req.user.id !== userId) return res.status(403).send("Acesso negado");

  const user = getUserById(userId);
  if (!user || !user.credentials) return res.status(400).send("Sem credenciais");

  const options = generateAuthenticationOptions({
    allowCredentials: user.credentials.map(c => ({
      id: c.credential.id,
      type: c.credentialType,
      transports: c.transports || ["internal"],
    })),
    rpID,
  });

  res.json({ ...options, challenge: options.challenge });
});

// Verificar autenticação
router.post("/authn/verify/:userId", authMiddleware, async (req, res) => {
  const { userId } = req.params;
  if (req.user.id !== userId) return res.status(403).send("Acesso negado");

  const { assertionResponse } = req.body;
  const user = getUserById(userId);
  if (!user || !user.credentials) return res.status(400).send("Sem credenciais");

  const authenticator = user.credentials[0].credential;

  try {
    const verification = await verifyAuthenticationResponse({
      response: assertionResponse,
      expectedChallenge: assertionResponse.response.clientDataJSON.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential: authenticator,
    });

    if (!verification.verified) return res.status(400).send("Falha na autenticação");
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).send("Erro interno");
  }
});

export default router;
