import { connect } from "node:tls";
import type { PeerCertificate } from "node:tls";
import type { TlsMetadata } from "./index.js";

export interface CollectTlsMetadataOptions {
  port?: number;
  timeoutMs?: number;
  rejectUnauthorized?: boolean;
}

export async function collectTlsMetadata(target: string | URL, options: CollectTlsMetadataOptions = {}): Promise<TlsMetadata | undefined> {
  const url = typeof target === "string" ? new URL(target.includes("://") ? target : `https://${target}`) : target;
  if (url.protocol !== "https:") return undefined;
  const port = options.port ?? (url.port ? Number(url.port) : 443);
  const timeoutMs = options.timeoutMs ?? 5_000;

  return await new Promise<TlsMetadata | undefined>((resolve) => {
    const socket = connect({
      host: url.hostname,
      port,
      servername: url.hostname,
      rejectUnauthorized: options.rejectUnauthorized ?? false,
      timeout: timeoutMs
    });
    const done = (metadata?: TlsMetadata): void => {
      socket.removeAllListeners();
      socket.destroy();
      resolve(metadata);
    };
    socket.once("secureConnect", () => {
      const certificate = socket.getPeerCertificate();
      if (!certificate || Object.keys(certificate).length === 0) return done(undefined);
      done({
        authorized: socket.authorized,
        authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
        issuer: distinguishedName(certificate.issuer),
        subject: distinguishedName(certificate.subject),
        validFrom: certificate.valid_from,
        validTo: certificate.valid_to,
        fingerprint256: certificate.fingerprint256,
        serialNumber: certificate.serialNumber
      });
    });
    socket.once("timeout", () => done(undefined));
    socket.once("error", () => done(undefined));
  });
}

function distinguishedName(value: PeerCertificate["issuer"]): string | undefined {
  if (!value) return undefined;
  const entries = Object.entries(value)
    .filter(([, item]) => typeof item === "string" && item)
    .map(([key, item]) => `${key}=${item}`);
  return entries.length ? entries.join(", ") : undefined;
}
