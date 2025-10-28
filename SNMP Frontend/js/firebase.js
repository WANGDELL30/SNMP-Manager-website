// ./js/firebase.js  — kompatibel dengan window.__firebase_config berbentuk Object
import { initializeApp } from "https://www.gstatic.com/firebasejs/10.14.1/firebase-app.js";
import { getFirestore } from "https://www.gstatic.com/firebasejs/10.14.1/firebase-firestore.js";

let firebaseApp = null;
let db = null;

/**
 * Mengembalikan instance Firestore jika sudah siap
 */
export function getDb() {
  return db;
}

/**
 * Mengecek apakah Firestore sudah siap digunakan
 */
export function isFirebaseReady() {
  return !!db;
}

/**
 * Inisialisasi Firebase secara aman:
 * - Menerima window.__firebase_config baik dalam bentuk string JSON atau Object langsung
 * - Tidak menghentikan aplikasi kalau gagal (hanya log error)
 */
(function initFirebase() {
  try {
    const raw = window.__firebase_config ?? null;
    if (!raw) {
      console.info("[firebase] no config provided → skipping init");
      return;
    }

    // Deteksi format: string → parse, object → langsung
    const cfg = typeof raw === "string" ? JSON.parse(raw) : raw;
    firebaseApp = initializeApp(cfg);
    db = getFirestore(firebaseApp);
    console.log("[firebase] initialized ✅");
  } catch (err) {
    console.error("[firebase] init failed:", err);
  }
})();
