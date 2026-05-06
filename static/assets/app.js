const MAX_SECRET_BYTES = 64 * 1024;

const createView = document.querySelector("#create-view");
const revealView = document.querySelector("#reveal-view");
const createForm = document.querySelector("#create-form");
const secretInput = document.querySelector("#secret");
const charCount = document.querySelector("#char-count");
const result = document.querySelector("#result");
const shareURL = document.querySelector("#share-url");
const copyLink = document.querySelector("#copy-link");
const revealButton = document.querySelector("#reveal-button");
const secretOutput = document.querySelector("#secret-output");
const copySecret = document.querySelector("#copy-secret");
const statusBox = document.querySelector("#status");

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function setStatus(message, kind = "info") {
  statusBox.textContent = message;
  statusBox.dataset.kind = kind;
}

function clearStatusSoon() {
  window.setTimeout(() => {
    statusBox.textContent = "";
    statusBox.removeAttribute("data-kind");
  }, 4200);
}

function requireWebCrypto() {
  if (!window.crypto?.subtle) {
    throw new Error("Web Crypto is unavailable; use a modern browser over HTTPS or localhost.");
  }
}

function bytesToBase64URL(bytes) {
  let binary = "";
  for (let index = 0; index < bytes.length; index += 0x8000) {
    const chunk = bytes.subarray(index, index + 0x8000);
    binary += String.fromCharCode(...chunk);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function base64URLToBytes(value) {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const padded = normalized.padEnd(normalized.length + ((4 - (normalized.length % 4)) % 4), "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function randomToken(byteLength) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return bytesToBase64URL(bytes);
}

async function consumeVerifier(id, rawKey) {
  const context = encoder.encode(`paper consume v1\0${id}\0`);
  const input = new Uint8Array(context.length + rawKey.length);
  input.set(context);
  input.set(rawKey, context.length);
  return bytesToBase64URL(new Uint8Array(await crypto.subtle.digest("SHA-256", input)));
}

async function readError(response) {
  const text = await response.text();
  if (text.length === 0) {
    return `${response.status} ${response.statusText}`;
  }

  try {
    const payload = JSON.parse(text);
    if (payload.error) {
      return payload.error;
    }
  } catch (error) {
    return `${response.status} ${response.statusText}: ${text}`;
  }

  return `${response.status} ${response.statusText}: ${text}`;
}

async function copyText(value, label) {
  try {
    await navigator.clipboard.writeText(value);
    setStatus(`${label} copied. Tiny victory parade authorized.`, "ok");
    clearStatusSoon();
  } catch (error) {
    setStatus(`Clipboard failed: ${error.message}`, "error");
  }
}

function updateByteCount() {
  const bytes = encoder.encode(secretInput.value).length;
  charCount.textContent = `${bytes.toLocaleString()} bytes`;
  charCount.style.color = bytes > MAX_SECRET_BYTES ? "#6f1715" : "";
}

async function sealSecret(secret) {
  requireWebCrypto();

  const plaintext = encoder.encode(secret);
  if (plaintext.length === 0) {
    throw new Error("Secret text is required.");
  }
  if (plaintext.length > MAX_SECRET_BYTES) {
    throw new Error(`Secret is ${plaintext.length} bytes; max is ${MAX_SECRET_BYTES} bytes.`);
  }

  const key = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"],
  );
  const rawKey = new Uint8Array(await crypto.subtle.exportKey("raw", key));
  const nonce = new Uint8Array(12);
  crypto.getRandomValues(nonce);

  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce },
    key,
    plaintext,
  ));

  const id = randomToken(16);

  return {
    id,
    key: bytesToBase64URL(rawKey),
    ciphertext: bytesToBase64URL(ciphertext),
    nonce: bytesToBase64URL(nonce),
    consumeVerifier: await consumeVerifier(id, rawKey),
  };
}

async function createSecret(event) {
  event.preventDefault();

  const button = createForm.querySelector("button[type='submit']");
  button.disabled = true;
  setStatus("Sealing locally before the server sees anything...", "info");

  try {
    const sealed = await sealSecret(secretInput.value);
    const response = await fetch("/api/secrets", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        id: sealed.id,
        ciphertext: sealed.ciphertext,
        nonce: sealed.nonce,
        consumeVerifier: sealed.consumeVerifier,
      }),
    });

    if (!response.ok) {
      throw new Error(await readError(response));
    }

    const payload = await response.json();
    const url = `${payload.url}#${sealed.key}`;
    shareURL.value = url;
    result.hidden = false;
    secretInput.value = "";
    updateByteCount();
    setStatus("Secret sealed. Server received encrypted confetti only.", "ok");
    clearStatusSoon();
  } catch (error) {
    setStatus(`Could not create secret: ${error.message}`, "error");
  } finally {
    button.disabled = false;
  }
}

async function revealKeyMaterial() {
  const hash = window.location.hash.slice(1);
  if (hash.length === 0) {
    throw new Error("This URL has no #decryption-key fragment. Without it, the note is just fancy garbage.");
  }

  const rawKey = base64URLToBytes(hash);
  const key = await crypto.subtle.importKey(
    "raw",
    rawKey,
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );

  return { key, rawKey };
}

async function revealSecret() {
  revealButton.disabled = true;
  setStatus("Burning the server copy and decrypting locally...", "info");

  try {
    requireWebCrypto();
    const { key, rawKey } = await revealKeyMaterial();
    const id = window.location.pathname.split("/").pop();
    const response = await fetch(`/api/secrets/${encodeURIComponent(id)}/consume`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        consumeVerifier: await consumeVerifier(id, rawKey),
      }),
    });

    if (!response.ok) {
      throw new Error(await readError(response));
    }

    const payload = await response.json();
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: base64URLToBytes(payload.nonce) },
      key,
      base64URLToBytes(payload.ciphertext),
    );

    secretOutput.textContent = decoder.decode(plaintext);
    secretOutput.hidden = false;
    copySecret.hidden = false;
    revealButton.hidden = true;
    window.history.replaceState(null, "", window.location.pathname);
    setStatus("Revealed. Server copy is ash now.", "ok");
    clearStatusSoon();
  } catch (error) {
    setStatus(`Could not reveal secret: ${error.message}`, "error");
    revealButton.disabled = false;
  }
}

function boot() {
  const isReveal = window.location.pathname.startsWith("/s/");
  createView.hidden = isReveal;
  revealView.hidden = !isReveal;

  if (!isReveal) {
    secretInput.addEventListener("input", updateByteCount);
    createForm.addEventListener("submit", createSecret);
    copyLink.addEventListener("click", () => copyText(shareURL.value, "Link"));
    updateByteCount();
    return;
  }

  revealButton.addEventListener("click", revealSecret);
  copySecret.addEventListener("click", () => copyText(secretOutput.textContent, "Secret"));
  if (window.location.hash.length === 0) {
    setStatus("Missing the #key fragment. This link cannot decrypt the stored ciphertext.", "error");
  }
}

boot();
