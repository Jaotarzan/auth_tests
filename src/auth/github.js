import passport from "passport";
import { Strategy as GithubStrategy } from "passport-github2"
import { getOrCreateUser } from "../users.js";

passport.use(new GithubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: "https://auth-tests.onrender.com/auth/github/callback"
}, async (accessToken, refreshToken, profile, done) => {
    try {
        const user = await getOrCreateUser(profile);
        console.log("GitHub user profile:", profile);
        done(null, user);
    } catch (error) {
        done(error);
    }
}));