import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { getOrCreateUser } from "../users.js";


passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "https://auth-tests.onrender.com/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
    try {
        const user = await getOrCreateUser(profile);
        console.log("Google user profile:", profile);
        done(null, user);
    } catch (error) {
        done(error);
    }
}));