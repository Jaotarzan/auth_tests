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
      id: c.credentialID,            // já é ArrayBuffer
      type: "public-key",
      transports: c.transports || ["internal"],
    })),
    rpID,
  });

  // salvar challenge em memória (não mexe no objeto enviado ao cliente)
  challenges[userId] = options.challenge;

  res.json(options); // envia cru, sem base64url
});

router.post("/authn/verify/:userId", authMiddleware, async (req, res) => {
  const { userId } = req.params;
  if (req.user.id !== userId) return res.status(403).send("Acesso negado");

  const { assertionResponse } = req.body;
  const user = getUserById(userId);
  if (!user || !user.credentials) return res.status(400).send("Sem credenciais");

  // localizar o autenticador pelo credentialID
  const authenticator = user.credentials.find(c =>
    c.credentialID.equals(Buffer.from(assertionResponse.id, "base64url"))
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

    if (!verification.verified) return res.status(400).send("Falha na autenticação");

    // remover challenge após verificação
    delete challenges[userId];

    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).send("Erro interno");
  }
});
