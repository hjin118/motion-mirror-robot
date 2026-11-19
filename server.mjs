// 로컬 서버: PC용 HTTP(localhost) + 휴대폰용 HTTPS(자체 서명 인증서)
// 실행: node server.mjs
import http from "node:http";
import https from "node:https";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { execFileSync, spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const HTTP_PORT = Number(process.env.HTTP_PORT || 8080);
const HTTPS_PORT = Number(process.env.HTTPS_PORT || 8443);
const CERT_DIR = path.join(ROOT, "cert");

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
};

function lanAddresses() {
  return Object.values(os.networkInterfaces())
    .flat()
    .filter((i) => i && i.family === "IPv4" && !i.internal)
    .map((i) => i.address);
}

function findOpenSSL() {
  const candidates = [
    "openssl",
    "C:\\Program Files\\Git\\usr\\bin\\openssl.exe",
    "C:\\Program Files\\Git\\mingw64\\bin\\openssl.exe",
  ];
  for (const c of candidates) {
    try { execFileSync(c, ["version"], { stdio: "ignore" }); return c; } catch {}
  }
  return null;
}

function ensureCert(ips) {
  const keyFile = path.join(CERT_DIR, "key.pem");
  const certFile = path.join(CERT_DIR, "cert.pem");
  const ipsFile = path.join(CERT_DIR, "ips.txt");
  const ipList = ["127.0.0.1", ...ips].join(",");
  const fresh = fs.existsSync(keyFile) && fs.existsSync(certFile) &&
    fs.existsSync(ipsFile) && fs.readFileSync(ipsFile, "utf8") === ipList;
  if (!fresh) {
    const openssl = findOpenSSL();
    if (!openssl) return null;
    fs.mkdirSync(CERT_DIR, { recursive: true });
    const cnf = path.join(CERT_DIR, "openssl.cnf");
    const san = ["DNS.1 = localhost", ...["127.0.0.1", ...ips].map((ip, i) => `IP.${i + 1} = ${ip}`)].join("\n");
    fs.writeFileSync(cnf, `[req]
prompt = no
distinguished_name = dn
x509_extensions = v3
[dn]
CN = motion-mirror-local
[v3]
subjectAltName = @alt
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
[alt]
${san}
`);
    execFileSync(openssl, [
      "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "365",
      "-keyout", keyFile, "-out", certFile, "-config", cnf,
    ], { stdio: "ignore" });
    fs.writeFileSync(ipsFile, ipList);
  }
  return { key: fs.readFileSync(keyFile), cert: fs.readFileSync(certFile) };
}

/* ---------- Cloudflare 무료 터널 (어디서나 접속 가능한 https 주소) ---------- */
let publicUrl = null;
let tunnelProc = null;

function findCloudflared() {
  const candidates = [
    "cloudflared",
    "C:\\Program Files (x86)\\cloudflared\\cloudflared.exe",
    "C:\\Program Files\\cloudflared\\cloudflared.exe",
    path.join(os.homedir(), "AppData\\Local\\Microsoft\\WinGet\\Links\\cloudflared.exe"),
  ];
  for (const c of candidates) {
    try { execFileSync(c, ["--version"], { stdio: "ignore" }); return c; } catch {}
  }
  return null;
}

function startTunnel() {
  if (process.env.NO_TUNNEL) return;
  const bin = findCloudflared();
  if (!bin) {
    console.log("\n[안내] cloudflared가 없어 공개 주소를 만들지 않습니다. 설치: winget install Cloudflare.cloudflared");
    return;
  }
  console.log("\n[터널] 공개 https 주소를 만드는 중…");
  tunnelProc = spawn(bin, ["tunnel", "--no-autoupdate", "--url", `http://localhost:${HTTP_PORT}`], {
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  const onData = (buf) => {
    const m = buf.toString().match(/https:\/\/[a-z0-9-]+\.trycloudflare\.com/);
    if (m && !publicUrl) {
      publicUrl = m[0];
      console.log("\n==============================================================");
      console.log(`  휴대폰에서 이 주소를 여세요 (Wi-Fi/LTE 모두 가능):`);
      console.log(`  ${publicUrl}`);
      console.log(`  또는 PC에서 http://localhost:${HTTP_PORT} 을 열고 QR 코드를 스캔`);
      console.log("==============================================================\n");
    }
  };
  tunnelProc.stdout.on("data", onData);
  tunnelProc.stderr.on("data", onData);
  tunnelProc.on("exit", (code) => {
    if (!publicUrl) console.log(`[터널] 시작하지 못했습니다 (코드 ${code}). 같은 Wi-Fi 주소를 사용하세요.`);
    publicUrl = null;
  });
}
for (const sig of ["SIGINT", "SIGTERM", "exit"]) {
  process.on(sig, () => { tunnelProc?.kill(); if (sig !== "exit") process.exit(0); });
}

function handler(req, res) {
  let urlPath = decodeURIComponent(new URL(req.url, "http://x").pathname);
  if (urlPath === "/api/urls") {
    res.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "no-store" });
    res.end(JSON.stringify({
      public: publicUrl,
      lan: lanAddresses().map((ip) => `https://${ip}:${HTTPS_PORT}`),
    }));
    return;
  }
  if (urlPath === "/") urlPath = "/index.html";
  const file = path.normalize(path.join(ROOT, urlPath));
  if (!file.startsWith(ROOT) || file.startsWith(CERT_DIR)) {
    res.writeHead(403).end("Forbidden");
    return;
  }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404).end("Not found"); return; }
    res.writeHead(200, {
      "Content-Type": MIME[path.extname(file).toLowerCase()] || "application/octet-stream",
      "Cache-Control": "no-store",
    });
    res.end(data);
  });
}

const ips = lanAddresses();
http.createServer(handler).listen(HTTP_PORT, () => {
  console.log(`\n[PC]     http://localhost:${HTTP_PORT}`);
  startTunnel();
});

const tls = ensureCert(ips);
if (tls) {
  https.createServer(tls, handler).listen(HTTPS_PORT, () => {
    console.log(`[휴대폰] 같은 Wi-Fi에서 아래 주소로 접속하세요:`);
    for (const ip of ips) console.log(`         https://${ip}:${HTTPS_PORT}`);
    console.log(`\n  · "안전하지 않음/개인 정보 보호" 경고가 나오면 [고급] → [계속 진행]을 누르세요.`);
    console.log(`  · 자체 서명 인증서라서 나오는 경고이며, 내 PC에서만 쓰는 연결입니다.`);
    console.log(`  · Windows 방화벽 창이 뜨면 [개인 네트워크]에서 허용하세요.\n`);
  });
} else {
  console.log("\n[경고] openssl을 찾지 못해 HTTPS 서버를 켜지 못했습니다. 휴대폰 카메라는 HTTPS가 필요합니다.");
}
