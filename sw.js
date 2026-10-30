// QC Time service worker — ทำให้ติดตั้งเป็นแอปได้ และเปิดหน้าแอปได้แม้สัญญาณไม่ดี
// • หน้าแอป (index.html): ดึงจากเน็ตก่อน เพื่อให้ได้เวอร์ชันล่าสุดเสมอ · ออฟไลน์ใช้ตัวที่เก็บไว้
// • รูป/ไอคอน: ใช้ตัวที่เก็บไว้ทันที แล้วอัปเดตเบื้องหลัง
// • ข้อมูล /api: ไม่เก็บเลย (ข้อมูลจริงต้องมาจากเซิร์ฟเวอร์ทุกครั้ง)
const CACHE = "qctime-v1";
const SHELL = ["./", "./index.html", "./manifest.webmanifest", "./assets/icon-192.png", "./assets/icon-512.png", "./assets/favicon.png"];

self.addEventListener("install", e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).then(() => self.skipWaiting()));
});
self.addEventListener("activate", e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener("fetch", e => {
  const req = e.request; const url = new URL(req.url);
  if (req.method !== "GET" || url.origin !== location.origin || url.pathname.startsWith("/api")) return; // ไม่ยุ่งกับ API และเว็บอื่น
  if (req.mode === "navigate" || url.pathname.endsWith(".html") || url.pathname === "/") {
    e.respondWith(fetch(req).then(res => { const copy = res.clone(); caches.open(CACHE).then(c => c.put("./index.html", copy)); return res; })
      .catch(() => caches.match("./index.html")));
    return;
  }
  e.respondWith(caches.match(req).then(hit => {
    const net = fetch(req).then(res => { if (res.ok) { const copy = res.clone(); caches.open(CACHE).then(c => c.put(req, copy)); } return res; }).catch(() => hit);
    return hit || net;
  }));
});
