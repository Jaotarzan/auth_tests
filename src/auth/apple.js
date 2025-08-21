import passport from "passport";
import AppleStrategy from "passport-apple";
import { getOrCreateUser } from "../users.js";

passport.use(new AppleStrategy({
    clientID: process.env.APPLE_CLIENT_ID,
    teamID: process.env.APPLE_TEAM_ID,
    keyID: process.env.APPLE_KEY_ID,
    privateKey: process.env.APPLE_PRIVATE_KEY,
    callbackURL: "http://192.168.0.103:3000/auth/apple/callback"
}, async (accessToken, refreshToken, profile, done) => {
    try {
        const user = await getOrCreateUser(profile);
        done(null, user);
    } catch (error) {
        done(error);
    }
}));