import { Router } from "express";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} from "@simplewebauthn/server";
import { getAllUsers, getUserById } from "../users.js";
import { authMiddleware } from "../middlewares/auth.js";
import base64url from "base64url";
import { Buffer } from "buffer";

const router = Router();
const rpID = "eusoulindo.local";
const origin = `https://${rpID}:5173`;

// -----------------------
// Registro WebAuthn
// -----------------------
router.get("/register/options/:userId", authMiddleware, async (req, res) => {
  const { userId } = req.params;
  if (req.user.id !== userId) return res.status(403).send("Acesso negado");

  const user = getUserById(userId);
  if (!user) return res.status(404).send("Usuário não encontrado");
  console.log("Usuário encontrado:", user);

  const options = await generateRegistrationOptions({
    rpName: "Meu App",
    rpID,
    // userID agora como Buffer (não string)
    userID: Buffer.from(user.id, "utf8"),
    userName: user.username,
  });
  console.log("Opções de registro:", options);
  // Converter challenge e user.id para base64url para frontend
  options.challenge = base64url.encode(options.challenge);
  options.user.id = base64url.encode(options.user.id);

  res.json(options);
});

router.post("/register/verify/:userId", authMiddleware, async (req, res) => {
  const { userId } = req.params;
  if (req.user.id !== userId) return res.status(403).send("Acesso negado");

  const { attestationResponse } = req.body;
  const user = getUserById(userId);
  if (!user) return res.status(404).send("Usuário não encontrado");
  console.log("Usuário encontrado para registro:", user);
  console.log("Resposta de atestação:", attestationResponse);

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
      id: c.credential.id,
      type: c.credentialType,
      transports: c.transports || ["internal"],
    })),
    rpID,
  });

  // Converter challenge e allowCredentials[].id para base64url
  options.challenge = base64url.encode(options.challenge);
  options.allowCredentials = options.allowCredentials.map(c => ({
    ...c,
    id: base64url.encode(c.id),
  }));

  res.json(options);
});

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
