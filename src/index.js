import dotenv from "dotenv";
dotenv.config();

import express from "express";
import passport from "passport";
import cors from "cors";

import authRoutes from "./routes/auth.js";
import webauthnRoutes from "./routes/webauthn.js";
import "./auth/passport.js";

const app = express();

// Configuração de CORS
const allowedOrigins = [
  "https://EuSouLindo.local:5173", // frontend dev
  "https://auth-tests.onrender.com" // frontend produção
];

app.use(cors({
  origin: allowedOrigins,
}));

// Middleware para parsing de JSON
app.use(express.json());

// Inicialização do Passport
app.use(passport.initialize());

// Rotas
app.use("/auth", authRoutes);
app.use("/webauthn", webauthnRoutes);

// Rota principal (exemplo, apenas teste)
app.get("/", (req, res) => {
  res.json({ message: "API funcionando sem cookies!" });
});

// Inicialização do servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server rodando na porta ${PORT}`);
});
