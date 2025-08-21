import { Router } from "express";
import { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } from "@simplewebauthn/server";
import { getAllUsers } from "../users.js";

const router = Router();
const rpID = "EuSouLindo.local";
const origin = `${rpID}:5173`;

router.get("/register/options", async (req, res) => {
    try {
        const users = getAllUsers();
        const user = users[0];
        console.log("User in session for registration:", user);
        if (!user || !user.id || !user.username) {
            console.error("Missing user information in session", user);
            return res.status(400).send("User information is missing");
        }
        const options = await generateRegistrationOptions({
            rpName: "test",
            rpID,
            userID: Buffer.from(user.id, "utf8"),
            userName: user.username,
        });
        req.session.challenge = options.challenge;
        console.log("Generated registration options:", options);
        res.json(options);
    } catch (error) {
        console.error("Error in /register/options:", error);
        res.status(500).send("Internal server error");
    }
});

router.post("/register/verify", async (req, res) => {
    try {
        console.log("Verifying registration response:", req.body);
        const verification = await verifyRegistrationResponse({
            response: req.body,
            expectedChallenge: req.session.challenge,
            expectedOrigin: origin,
            expectedRPID: rpID,
        });
        console.log("Verification result:", verification);
        
        if (!verification.verified) {
            console.error("Verification failed");
            return res.status(400).send("Verification failed");
        }

        const user = getUserById(req.user.id);
        if (!user) {
            console.error("User not found");
            return res.status(404).send("User not found");
        }

        if (!user.credentials) {
            user.credentials = [];
        }

        user.credentials.push(verification.registrationInfo);
        res.json({ success: verification.verified });
    } catch (error) {
        console.error("Registration verification error:", error);
        res.status(500).send("Internal server error");
    }
});

router.get("/authn/options", async (req, res) => {
    try {
        const user = getUserById(req.user.id);
        if (!user || !user.credentials || user.credentials.length === 0) {
            console.error("No credentials found for user");
            return res.status(400).send("No credentials found for user");
        }
        const options = await generateAuthenticationOptions({
            allowCredentials: user.credentials.map(cred => ({
                id: cred.credential.id,
                type: cred.credentialType,
                transports: cred.transports || ["internal"],
            })),
            rpID,
        });
        console.log("Generated authentication options:", options); // Log para depuração
        req.session.currentChallenge = options.challenge;
        res.json(options);
    } catch (error) {
        console.error("Error in /authn/options:", error);
        res.status(500).send("Internal server error");
    }
});

router.post("/authn/verify", async (req, res) => {
    try {
        console.log("Verifying authentication response:", req.body);

        // Decodificar e converter o userHandle para string
        const userHandle = Buffer.from(req.body.response.userHandle, "base64").toString("utf8");
        console.log("Decoded userHandle:", userHandle);

        // Buscar usuário pelo userHandle
        const user = getUserById(userHandle);
        if (!user) {
            console.error("User not found for userHandle:", userHandle);
            return res.status(404).send("User not found");
        }

        if (!user.credentials || user.credentials.length === 0) {
            console.error("No credentials found for user:", userHandle);
            return res.status(400).send("No credentials found for user");
        }

        // Usar o objeto authenticator diretamente
        const authenticator = user.credentials[0].credential;
        console.log("Authenticator data before verification:", authenticator);

        // Validar tipos e converter se necessário
        if (!(authenticator.counter >= 0)) {
            console.error("Invalid counter value or type:", authenticator.counter);
        }
        if (!(authenticator.publicKey instanceof Uint8Array)) {
            console.error("Invalid publicKey type, converting to Uint8Array:", authenticator.publicKey);
            authenticator.publicKey = new Uint8Array(authenticator.publicKey);
        }

        console.log("Validated authenticator data:", {
            counter: authenticator.counter,
            publicKey: authenticator.publicKey,
        });

        const verification = await verifyAuthenticationResponse({
            response: req.body,
            expectedChallenge: req.session.currentChallenge,
            expectedOrigin: origin,
            expectedRPID: rpID,
            credential: authenticator,
        });

        console.log("Authentication verification result:", verification);

        if (!verification.verified) {
            console.error("Authentication failed for user:", userHandle);
            return res.status(400).send("Authentication failed");
        }

        res.json({
            success: verification.verified,
            user: {
                id: user.id,
                name: user.name,
                credentials: user.credentials
            }
        });
    } catch (error) {
        console.error("Authentication verification error:", error);
        res.status(500).send("Internal server error");
    }
});

export default router;