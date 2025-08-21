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

// Rota para gerar opções de registro
router.get("/register/options", authMiddleware, async (req, res) => {
  const users = getAllUsers();
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).send("Usuário não encontrado");

  const options = generateRegistrationOptions({
    rpName: "Meu App",
    rpID,
    userID: Buffer.from(user.id, "utf8"),
    userName: user.username,
  });

  // Envia o challenge junto com a resposta
  res.json({ ...options, challenge: options.challenge });
});

// Rota para verificar registro
router.post("/register/verify", authMiddleware, async (req, res) => {
  const { response, challenge } = req.body; // challenge enviado pelo frontend
  try {
    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
    });

    if (!verification.verified) return res.status(400).send("Falha no registro");

    const user = getUserById(req.user.id);
    if (!user.credentials) user.credentials = [];
    user.credentials.push(verification.registrationInfo);

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).send("Erro interno");
  }
});

// Opções de autenticação
router.get("/authn/options", authMiddleware, async (req, res) => {
  const user = getUserById(req.user.id);
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
router.post("/authn/verify", authMiddleware, async (req, res) => {
  const { response, challenge } = req.body;
  const user = getUserById(req.user.id);
  if (!user || !user.credentials) return res.status(400).send("Sem credenciais");

  const authenticator = user.credentials[0].credential;

  try {
    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: challenge,
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
