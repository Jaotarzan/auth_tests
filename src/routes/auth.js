import { Router } from "express";
import passport from "passport";
import jwt from "jsonwebtoken";

const router = Router();
const FRONTEND_URL = "https://eusoulindo.local:5173";

// Helper para gerar token JWT
const generateToken = (user) => {
  return jwt.sign(
    { id: user.id, username: user.username },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );
};

// Google
router.get("/google", passport.authenticate("google", { scope: ["profile", "email"] }));

router.get("/google/callback",
  passport.authenticate("google", { session: false, failureRedirect: "/fail" }),
  (req, res) => {
    const token = generateToken(req.user);
    res.redirect(`${FRONTEND_URL}/dashboard?token=${token}`);
  }
);

// GitHub
router.get("/github", passport.authenticate("github", { scope: ["user:email"] }));

router.get("/github/callback",
  passport.authenticate("github", { session: false, failureRedirect: "/fail" }),
  (req, res) => {
    console.log("ocara q presica exixtir", req.user);
    const token = generateToken(req.user);
    res.redirect(`${FRONTEND_URL}/dashboard?token=${token}`);
  }
);

// Microsoft
router.get("/microsoft", passport.authenticate("azuread-openidconnect"));

router.post("/microsoft/callback",
  passport.authenticate("azuread-openidconnect", { session: false, failureRedirect: "/fail" }),
  (req, res) => {
    const token = generateToken(req.user);
    res.redirect(`${FRONTEND_URL}/dashboard?token=${token}`);
  }
);

// Logout: só no frontend
router.get("/logout", (req, res) => {
  res.redirect(FRONTEND_URL);
});

export default router;
