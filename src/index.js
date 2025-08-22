import dotenv from "dotenv";
dotenv.config();

import express from "express";
import passport from "passport";
import cors from "cors";

import authRoutes from "./routes/auth.js";
import webauthnRoutes from "./routes/webauthn.js";
import "./auth/passport.js";
import { authMiddleware } from "./middlewares/auth.js";

const app = express();

// Configuração de CORS
app.use(cors({
  origin: "https://frontend-ten-eta-85.vercel.app"
}));


// Middleware para parsing de JSON
app.use(express.json());

// Inicialização do Passport
app.use(passport.initialize());

// Rotas
app.use("/auth", authRoutes);
app.use("/webauthn", webauthnRoutes);

// Rota principal (exemplo, apenas teste)
app.get("/", authMiddleware, (req, res) => {
  try {
  console.log(req.user, 'precisa ser o caba')
  res.json({
    id: req.user.id,
    username: req.user.username,
    message: `Bem-vindo ${req.user.username}!`
  });
  } catch (error) {
    console.error("Erro ao processar requisição:", error);
    res.status(500).json({ error: "Erro interno do servidor" });
  }
});

// Inicialização do servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server rodando na porta ${PORT}`);
});
