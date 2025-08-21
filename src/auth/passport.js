import passport from "passport";
import { getUserById } from "../users.js";
// import "./apple";
import "./google.js";
import "./github.js";
import "./microsoft.js";

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    const user = getUserById(id);
    done(null, user);
});
