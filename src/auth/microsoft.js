import passport from "passport";
import { OIDCStrategy } from "passport-azure-ad";

passport.use(new OIDCStrategy({
  identityMetadata: "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration",
  clientID: process.env.MS_CLIENT_ID,
  clientSecret: process.env.MS_CLIENT_SECRET,
  responseType: "code",
  responseMode: "form_post",
  redirectUrl: "https://auth-tests.onrender.com/auth/microsoft/callback",
  allowHttpForRedirectUrl: true, // só em dev
  scope: ["openid", "profile", "email"]
}, (iss, sub, profile, accessToken, refreshToken, done) => {
  done(null, profile);
}));
