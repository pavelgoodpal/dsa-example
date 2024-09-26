import createFastify from "fastify";
import crypto from "crypto";
import * as u8a from "uint8arrays";
import { ed25519 } from "@noble/curves/ed25519";

const fastify = createFastify();

const sessionCahe: Record<string, {
  publicKey: string,
  message: string
}> = {};

fastify.post<{
  Body: { publicKey: string }
}>("/get-challenge", (req) => {
  const publicKey = req.body.publicKey;
  const sessionId = crypto.randomUUID();
  const message = JSON.stringify({
    msg: "Sign this to identify yourself",
    nonce: crypto.randomUUID()
  });
  sessionCahe[sessionId] = { message, publicKey };
  return {
    sessionId: sessionId,
    message: message
  };
});

fastify.post<{
  Body: {
    signature: string;
    sessionId: string;
  }
}>("/verify", async (req) => {
  const signature = req.body.signature;
  const sessionId = req.body.sessionId;
  const session = sessionCahe[sessionId];
  if (!session) {
    throw new Error();
  }
  const { message, publicKey } = session;
  const msgHash = crypto.createHash("sha256")
    .update(u8a.fromString(message))
    .digest();
  const isVerified = ed25519.verify(
    u8a.fromString(signature, "base64url"),
    msgHash,
    u8a.fromString(publicKey, "base64url")
  );
  return {
    isVerified
  };
});

async function main() {
  await fastify.listen({
    port: 8081,
    host: "127.0.0.1"
  });
}

main();