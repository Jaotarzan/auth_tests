import dotenv from "dotenv";
dotenv.config();

import express from "express";
import session from "express-session";
import passport from "passport";
import cors from "cors";

import authRoutes from "./routes/auth.js";
import webauthnRoutes from "./routes/webauthn.js";
import "./auth/passport.js";

const app = express();

// Configuração de CORS
app.use(cors({
  origin: ["http://192.168.0.103:5173", "https://auth-tests.onrender.com"],
  credentials: true // Permitir envio de cookies
}));

// Middleware para parsing de JSON
app.use(express.json());

// Configuração de sessão
app.use(session({
  secret: process.env.SESSION_SECRET || "default_secret", // Garantir que SESSION_SECRET está definido
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true, // Protege contra ataques XSS
    secure: false, // Deve ser true em produção com HTTPS
    sameSite: "lax" // Permite cookies em navegação cruzada segura
  }
}));

// Inicialização do Passport
app.use(passport.initialize());
app.use(passport.session());

// Middleware para verificar sessão e usuário
app.use((req, res, next) => {
  console.log("Sessão atual:", req.session);
  console.log("Usuário autenticado:", req.user);
  next();
});

// Rotas
app.use("/auth", authRoutes);
app.use("/webauthn", webauthnRoutes);

// Rota principal
app.get("/", (req, res) => {
  if (req.user) {
    res.json({
      id: req.user.id,
      name: req.user.username,
      message: `Welcome ${req.user.username} to the Express Social WebAuthn Example`
    });
  } else {
    res.status(401).json({ error: "User not authenticated" });
  }
});

// Inicialização do servidor
const PORT = process.env.PORT || 3000;

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server rodando na porta ${PORT}`);
});