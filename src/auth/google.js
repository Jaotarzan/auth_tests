import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { getOrCreateUser } from "../users.js";
import jwt from "jsonwebtoken";

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "https://auth-tests.onrender.com/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
    try {
        const user = await getOrCreateUser(profile);
        console.log("Google user profile:", profile);

        // Gerar JWT para o frontend
        const token = jwt.sign(
            { id: user.id, username: user.username },
            process.env.JWT_SECRET,
            { expiresIn: "1h" }
        );

        // Retornar o token junto com os dados do usuário
        done(null, { user, token });
    } catch (error) {
        done(error);
    }
}));
