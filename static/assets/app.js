const MAX_SECRET_BYTES = (() => {
  const meta = document.querySelector('meta[name="paper-max-bytes"]');
  const parsed = parseInt(meta?.content ?? "", 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 64 * 1024;
})();

const createView = document.querySelector("#create-view");
const revealView = document.querySelector("#reveal-view");
const createForm = document.querySelector("#create-form");
const composeColumn = document.querySelector(".compose-column");
const secretInput = document.querySelector("#secret");
const charCount = document.querySelector("#char-count");
const result = document.querySelector("#result");
const shareURL = document.querySelector("#share-url");
const copyLink = document.querySelector("#copy-link");
const expiryLine = document.querySelector("#expiry-line");
const revealButton = document.querySelector("#reveal-button");
const revealPanel = document.querySelector("#reveal-view");
const revealContent = revealPanel?.querySelector(".reveal-content") ?? null;
const revealTitle = document.querySelector("#reveal-title");
const revealLede = document.querySelector("#reveal-lede");
const sealedKicker = document.querySelector("#sealed-kicker");
const sealedTitle = document.querySelector("#sealed-title");
const sealedDescription = document.querySelector("#sealed-description");
const secretOutput = document.querySelector("#secret-output");
const secretOutputGroup = document.querySelector("#secret-output-group");
const copySecret = document.querySelector("#copy-secret");
const statusBox = document.querySelector("#status");
const howLink = document.querySelector(".how-link");
const fileIdCells = document.querySelectorAll("[data-file-id]");
const expiryCells = document.querySelectorAll("[data-expiry]");
const noteStatusCells = document.querySelectorAll("[data-note-status]");

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
    setStatus(`${label} copied.`, "ok");
    clearStatusSoon();
  } catch (error) {
    setStatus(`Clipboard failed: ${error.message}`, "error");
  }
}

function updateByteCount() {
  const bytes = encoder.encode(secretInput.value).length;
  charCount.textContent = `${bytes.toLocaleString()} / ${MAX_SECRET_BYTES.toLocaleString()}`;
  charCount.style.color = bytes > MAX_SECRET_BYTES ? "var(--error)" : "";
}

function formatTimestamp(date) {
  const yyyy = date.getUTCFullYear();
  const mm = String(date.getUTCMonth() + 1).padStart(2, "0");
  const dd = String(date.getUTCDate()).padStart(2, "0");
  const hh = String(date.getUTCHours()).padStart(2, "0");
  const min = String(date.getUTCMinutes()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd} ${hh}:${min}Z`;
}

function setFileId(id) {
  if (!id) {
    return;
  }
  fileIdCells.forEach((cell) => {
    cell.textContent = id;
  });
}

function setExpiry(value) {
  expiryCells.forEach((cell) => {
    cell.textContent = value;
  });
}

function setNoteStatus(value) {
  noteStatusCells.forEach((cell) => {
    cell.textContent = value;
  });
}

function formatExpiry(date) {
  const diffMs = date.getTime() - Date.now();
  const absDiff = Math.abs(diffMs);
  const minutes = Math.round(diffMs / 60_000);
  const hours = Math.round(diffMs / 3_600_000);
  const days = Math.round(diffMs / 86_400_000);

  let relative;
  try {
    const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
    if (absDiff >= 86_400_000) {
      relative = rtf.format(days, "day");
    } else if (absDiff >= 3_600_000) {
      relative = rtf.format(hours, "hour");
    } else {
      relative = rtf.format(minutes, "minute");
    }
  } catch {
    relative = date.toISOString();
  }

  const absolute = new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
  return `${relative} (${absolute})`;
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
  setStatus("Encrypting in this browser...", "info");

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
    // The API returns an absolute URL only when a public origin is configured,
    // and a path otherwise, which resolves against this origin. Neither is
    // built from the request Host header.
    const url = `${new URL(payload.url, window.location.origin)}#${sealed.key}`;
    shareURL.value = url;
    setFileId(sealed.id);
    if (payload.expiresAt) {
      const expiresAt = new Date(payload.expiresAt);
      if (!Number.isNaN(expiresAt.getTime())) {
        expiryLine.textContent = `Expires if unopened ${formatExpiry(expiresAt)}.`;
        expiryLine.hidden = false;
        setExpiry(formatTimestamp(expiresAt));
      }
    }
    setNoteStatus("Link ready");
    composeColumn.hidden = true;
    result.hidden = false;
    secretInput.value = "";
    updateByteCount();
    setStatus("Your private link is ready.", "ok");
    clearStatusSoon();

    result.scrollIntoView({ behavior: "smooth", block: "nearest" });
    shareURL.focus();
    shareURL.select();
  } catch (error) {
    setStatus(`Could not create secret: ${error.message}`, "error");
  } finally {
    button.disabled = false;
  }
}

async function revealKeyMaterial() {
  const hash = window.location.hash.slice(1);
  if (hash.length === 0) {
    throw new Error("This link is missing its #decryption-key fragment. Ask the sender for the complete URL.");
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
  setStatus("Destroying the server copy and decrypting here...", "info");

  try {
    requireWebCrypto();
    const { key, rawKey } = await revealKeyMaterial();
    const id = window.location.pathname.replace(/\/+$/, "").split("/").pop();
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
    if (secretOutputGroup) {
      secretOutputGroup.hidden = false;
    } else {
      secretOutput.hidden = false;
    }
    copySecret.hidden = false;
    revealButton.hidden = true;
    window.history.replaceState(null, "", window.location.pathname);
    revealTitle.textContent = "Your private note.";
    revealLede.textContent = "Decrypted only on this device. The encrypted server copy has been destroyed.";
    sealedKicker.textContent = "Opened safely";
    sealedTitle.textContent = "Nothing left on our server.";
    sealedDescription.textContent = "This was the only opening. Copy the note now if you need to keep it.";
    setNoteStatus("Opened");
    setExpiry("Destroyed");
    if (revealContent && !revealContent.querySelector(".opened-stamp")) {
      const stamp = document.createElement("span");
      stamp.className = "opened-stamp";
      stamp.setAttribute("aria-hidden", "true");
      stamp.textContent = "Opened";
      revealContent.appendChild(stamp);
    }
    setStatus("Opened. The server copy is gone.", "ok");
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
    document.title = "Paper — create a one-view private note";
    secretInput.addEventListener("input", updateByteCount);
    createForm.addEventListener("submit", createSecret);
    copyLink.addEventListener("click", () => copyText(shareURL.value, "Link"));
    updateByteCount();
    secretInput.focus();
    return;
  }

  document.title = "Paper — open a private note";
  howLink.href = "#reveal-privacy-note";
  const id = window.location.pathname.replace(/\/+$/, "").split("/").pop();
  setFileId(id);
  setNoteStatus("Unopened");
  setExpiry("On open");
  copySecret.addEventListener("click", () => copyText(secretOutput.textContent, "Note"));

  if (window.location.hash.length === 0) {
    revealButton.disabled = true;
    revealButton.setAttribute("aria-disabled", "true");
    setStatus("Missing #decryption-key fragment. Ask the sender for the complete private link.", "error");
    return;
  }

  revealButton.addEventListener("click", revealSecret);
}

boot();
