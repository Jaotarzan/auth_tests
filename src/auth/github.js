import passport from "passport";
import { Strategy as GithubStrategy } from "passport-github2"
import { getOrCreateUser } from "../users.js";
import jwt from "jsonwebtoken";

passport.use(new GithubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: "https://auth-tests.onrender.com/auth/github/callback"
}, async (accessToken, refreshToken, profile, done) => {
    try {
        const user = await getOrCreateUser(profile);
        console.log("GitHub user profile:", profile);

        // Gerar JWT para enviar ao frontend
        const token = jwt.sign(
            { id: user.id, username: user.username },
            process.env.JWT_SECRET,
            { expiresIn: "1h" }
        );

        // Em vez de salvar em sessão, retornamos o token
        done(null, { user, token });
    } catch (error) {
        done(error);
    }
}));
