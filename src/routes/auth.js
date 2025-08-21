import { Router } from "express";
import passport from "passport";

const router = Router();

// Google
router.get("/google", passport.authenticate("google", { scope: ["profile", "email"] }));
router.get("/google/callback", 
    passport.authenticate("google", { failureRedirect: "/fail" }),
    (req, res) => {
        res.redirect("/");
    }
);

//GitHub
router.get("/github", passport.authenticate("github", { scope: ["user:email"] }));
router.get("/github/callback", 
    passport.authenticate("github", { failureRedirect: "/fail" }),
    (req, res) => {
        res.redirect("/");
    }
);  

// Microsoft
router.get("/microsoft", passport.authenticate("azuread-openidconnect"));
router.post("/microsoft/callback", 
    passport.authenticate("azuread-openidconnect", { failureRedirect: "/fail" }),
    (req, res) => res.redirect("/")
);

//  Apple
// router.get("/apple", passport.authenticate("apple"));
// router.post("/apple/callback", 
//     passport.authenticate("apple", { failureRedirect: "/login" }),
//     (req, res) => res.redirect("/")
// );


//logout

router.get("/logout", (req, res) => {
    req.logout((err) => {
        if (err) {
            return res.status(500).send("Logout failed");
        }
        res.redirect("/");
    });
});

export default router;
