import crypto from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";
import * as u8a from "uint8arrays";

const config = {
  verifierURL: new URL("http://localhost:8081/"),
  secret: "my-secret"
};

const privateKey = crypto.createHash("sha256")
  .update(u8a.fromString(config.secret))
  .digest();

const publicKey = ed25519.getPublicKey(privateKey);

async function main() {
  const challengeEP = new URL("./get-challenge", config.verifierURL);
  const challengeResp = await fetch(challengeEP, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      publicKey: u8a.toString(publicKey, "base64url")
    })
  });
  if (!challengeResp.ok) {
    throw new Error(`Can get challenge from ${challengeEP.href}`);
  }
  const challenge = await challengeResp.json() as { message: string, sessionId: string };
  const msgBytes = u8a.fromString(challenge.message, "utf-8");
  const msgHash = crypto.createHash("sha256")
    .update(msgBytes)
    .digest();
  const signature = ed25519.sign(msgHash, privateKey);
  const verifyResp = await fetch(new URL("./verify", config.verifierURL), {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      sessionId: challenge.sessionId,
      signature: u8a.toString(signature, "base64url")
    })
  });
  if (!verifyResp.ok) {
    throw new Error("Verify response is not ok");
  }
  const verifyBody = await verifyResp.json();
  if (!verifyBody.isVerified) {
    throw new Error("Not ok");
  }
  console.log("Verified");
}

main();
