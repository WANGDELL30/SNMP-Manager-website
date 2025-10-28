/* ========= SNMP Manager Frontend (All-in-one) =========
   - Kompatibel dengan backend: SNMPBackendrealcode.py
   - Tersedia:
     showPage, runOp, doSet, toggleLive, clearTable, exportCSV
     ensureCharts, updateTempHumChart, updateVoltCurrChart
     resolveMib, browseMib (placeholder)
   ===================================================== */

(function () {
  // ====== Konfigurasi dasar ======
  const BACKEND =
    window.__backend_base_url ||
    (location.hostname === "localhost" || location.hostname === "127.0.0.1"
      ? "http://127.0.0.1:5000"
      : `${location.protocol}//${location.host}`);

  // ====== State ======
  let liveOn = true;
  let pollTimer = null;
  let rowsStore = []; // simpan semua rows table
  let tempHumChart = null;
  let voltCurrChart = null;

  // ====== Helper DOM ======
  const $ = (sel) => document.querySelector(sel);
  const $all = (sel) => Array.from(document.querySelectorAll(sel));

  function nowISO() {
    return new Date().toISOString();
  }

  // ====== Alert box ringan ======
  function showAlert(message, type = "info", timeout = 1800) {
    // type: info | success | warning | error
    let wrap = $("#alert-wrap");
    if (!wrap) {
      wrap = document.createElement("div");
      wrap.id = "alert-wrap";
      wrap.style.position = "fixed";
      wrap.style.top = "16px";
      wrap.style.right = "16px";
      wrap.style.display = "flex";
      wrap.style.flexDirection = "column";
      wrap.style.gap = "8px";
      wrap.style.zIndex = "9999";
      document.body.appendChild(wrap);
    }
    const box = document.createElement("div");
    box.style.padding = "10px 14px";
    box.style.borderRadius = "10px";
    box.style.boxShadow = "0 6px 18px rgba(0,0,0,.25)";
    box.style.color = "#fff";
    box.style.font = "14px/1.3 Inter, system-ui, sans-serif";
    box.style.opacity = "0.98";
    box.style.backdropFilter = "blur(8px)";
    box.style.transition = "transform .2s ease, opacity .2s ease";
    box.style.transform = "translateY(-6px)";
    box.textContent = message;

    const colors = {
      info: "#2563eb",
      success: "#16a34a",
      warning: "#d97706",
      error: "#dc2626",
    };
    box.style.background =
      `linear-gradient(120deg, ${colors[type] || colors.info}, #0f172a)`;

    wrap.appendChild(box);
    requestAnimationFrame(() => (box.style.transform = "translateY(0)"));

    setTimeout(() => {
      box.style.opacity = "0";
      box.style.transform = "translateY(-8px)";
      setTimeout(() => wrap.removeChild(box), 180);
    }, timeout);
  }

  // ====== Logging ======
  function log(...args) {
    const pre = $("#log");
    const line = `[${new Date().toLocaleTimeString()}] ${args
      .map((a) => (typeof a === "object" ? JSON.stringify(a) : String(a)))
      .join(" ")}`;
    if (pre) pre.textContent = `${pre.textContent}\n${line}`.trim();
    console.log("[LOG]", ...args);
  }

  // ====== Table helper ======
  function renderTableRows(newRows) {
    const tbody = $("#table-body");
    if (!tbody || !Array.isArray(newRows)) return;

    const frag = document.createDocumentFragment();
    newRows.forEach((row, idx) => {
      const tr = document.createElement("tr");
      tr.className = "border-b border-slate-800/40 hover:bg-slate-800/20";
      const tds = [
        String(rowsStore.length + idx + 1),
        row.name ?? "",
        row.oid ?? "",
        String(row.value ?? ""),
        row.unit ?? "",
        row.type ?? "",
        row.category ?? "",
        row.source ?? "",
        `${row.ip ?? ""}:${row.port ?? ""}`,
        row.ts ?? "",
      ];
      tds.forEach((txt) => {
        const td = document.createElement("td");
        td.className = "p-2";
        td.textContent = txt;
        tr.appendChild(td);
      });
      frag.appendChild(tr);
    });
    tbody.appendChild(frag);
  }

  function clearTable() {
    rowsStore = [];
    const tbody = $("#table-body");
    if (tbody) tbody.innerHTML = "";
    log("Table cleared");
    showAlert("Table cleared", "info");
  }

  function exportCSV() {
    if (!rowsStore.length) {
      showAlert("No data to export", "warning");
      return;
    }
    const header = [
      "name",
      "oid",
      "value",
      "unit",
      "type",
      "category",
      "source",
      "ip",
      "port",
      "ts",
    ];
    const lines = [header.join(",")];
    rowsStore.forEach((r) => {
      lines.push(
        [
          r.name,
          r.oid,
          r.value,
          r.unit,
          r.type,
          r.category,
          r.source,
          r.ip,
          r.port,
          r.ts,
        ]
          .map((v) => (v == null ? "" : String(v).replace(/,/g, " ")))
          .join(",")
      );
    });
    const blob = new Blob([lines.join("\n")], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = Object.assign(document.createElement("a"), {
      href: url,
      download: `snmp_table_${Date.now()}.csv`,
    });
    document.body.appendChild(a);
    a.click();
    URL.revokeObjectURL(url);
    document.body.removeChild(a);
    showAlert("CSV exported", "success");
  }

  // ====== Chart.js (Realtime smoothing) ======
  function ensureCharts() {
    const ctx1 = $("#tempHumidityChart");
    const ctx2 = $("#voltageCurrentChart");
    if (!ctx1 || !ctx2) return;

    // Config umum realtime: limit 50 titik, geser halus
    const commonOptions = {
      responsive: true,
      animation: { duration: 250, easing: "easeOutQuart" },
      interaction: { mode: "nearest", intersect: false },
      scales: {
        x: {
          type: "time",
          time: { unit: "second", tooltipFormat: "HH:mm:ss" },
          ticks: { autoSkip: true, maxTicksLimit: 8 },
          grid: { color: "rgba(148,163,184,.15)" },
        },
        y: {
          beginAtZero: false,
          grid: { color: "rgba(148,163,184,.15)" },
        },
      },
      plugins: {
        legend: { labels: { color: "#ddd" } },
        tooltip: { enabled: true },
      },
    };

    if (!tempHumChart) {
      tempHumChart = new Chart(ctx1, {
        type: "line",
        data: {
          datasets: [
            { label: "Temperature (°C)", data: [], tension: 0.25 },
            { label: "Humidity (%RH)", data: [], tension: 0.25 },
          ],
        },
        options: commonOptions,
      });
    }
    if (!voltCurrChart) {
      voltCurrChart = new Chart(ctx2, {
        type: "line",
        data: {
          datasets: [
            { label: "Voltage (V)", data: [], tension: 0.25 },
            { label: "Current (A)", data: [], tension: 0.25 },
          ],
        },
        options: commonOptions,
      });
    }
  }

  function appendPoint(chart, seriesIndex, value) {
    if (!chart) return;
    const ds = chart.data.datasets[seriesIndex];
    if (!ds) return;
    ds.data.push({ x: Date.now(), y: Number(value) });
    // keep at most 50 points
    if (ds.data.length > 50) ds.data.splice(0, ds.data.length - 50);
    chart.update("none");
  }

  function updateTempHumChart(temp, hum) {
    ensureCharts();
    if (typeof temp === "number") appendPoint(tempHumChart, 0, temp);
    if (typeof hum === "number") appendPoint(tempHumChart, 1, hum);
  }

  function updateVoltCurrChart(voltage, current) {
    ensureCharts();
    if (typeof voltage === "number") appendPoint(voltCurrChart, 0, voltage);
    if (typeof current === "number") appendPoint(voltCurrChart, 1, current);
  }

  // ====== Page switching ======
  function showPage(id) {
    $all(".page").forEach((p) => p.classList.remove("active"));
    const pg = document.getElementById(id);
    if (!pg) {
      console.warn("showPage: element not found ->", id);
      return;
    }
    pg.classList.add("active");

    // Saat buka monitoring -> pastikan chart siap
    if (id === "sensor-monitoring") ensureCharts();

    pg.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  // ====== SNMP Calls ======
  async function snmpCall(payload) {
    try {
      const res = await fetch(`${BACKEND}/snmp`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!res.ok) {
        const t = await res.text();
        throw new Error(`HTTP ${res.status}: ${t}`);
      }
      return await res.json();
    } catch (e) {
      showAlert(`SNMP call failed: ${e.message}`, "error", 3000);
      log("SNMP call failed:", e);
      throw e;
    }
  }

  function readForm() {
    return {
      ip: $("#ip")?.value?.trim() || "127.0.0.1",
      port: Number($("#port")?.value || 161),
      community: $("#community")?.value?.trim() || "public",
      version: $("#version")?.value || "v2c",
      oid: $("#oid")?.value?.trim() || "1.3.6.1.4.1.9999.1.2",
      v3: {
        user: $("#v3_user")?.value?.trim() || "",
        authProto: $("#v3_auth")?.value || "NONE",
        authKey: $("#v3_authKey")?.value || "",
        privProto: $("#v3_priv")?.value || "NONE",
        privKey: $("#v3_privKey")?.value || "",
      },
    };
  }

  async function runOp(operation) {
    const f = readForm();
    const payload = {
      operation,
      ip: f.ip,
      port: f.port,
      community: f.community,
      version: f.version,
      oid: f.oid,
      v3: f.version === "v3" ? f.v3 : undefined,
    };
    log("RUN", operation, payload);
    showAlert(`RUN ${operation.toUpperCase()}…`, "info", 900);

    const data = await snmpCall(payload);
    const newRows = (data.rows || []).map((r) => ({
      ...r,
      ts: r.ts || nowISO(),
      source: r.source || "backend",
    }));

    rowsStore.push(...newRows);
    renderTableRows(newRows);
    log(`RUN ${operation} -> ${newRows.length} row(s)`);

    // kalau hasil ada protokol dummy 9999 -> coba update chart
    const byName = Object.fromEntries(
      newRows.map((r) => [r.name, Number(r.value)])
    );
    if ("temperature" in byName || "humidity" in byName) {
      updateTempHumChart(byName.temperature, byName.humidity);
    }
    if ("voltage" in byName || "current" in byName) {
      updateVoltCurrChart(byName.voltage, byName.current);
    }

    showAlert(`${operation.toUpperCase()} OK (${newRows.length})`, "success");
    return data;
  }

  async function doSet() {
    const f = readForm();
    const setValue = prompt("Value for SET (string/int):", "");
    if (setValue == null) return;
    const payload = {
      operation: "set",
      ip: f.ip,
      port: f.port,
      community: f.community,
      version: f.version,
      oid: f.oid,
      setValue,
      v3: f.version === "v3" ? f.v3 : undefined,
    };
    log("RUN SET", payload);
    showAlert("RUN SET…", "info", 900);
    const data = await snmpCall(payload);
    const newRows = (data.rows || []).map((r) => ({
      ...r,
      ts: r.ts || nowISO(),
      source: r.source || "backend",
    }));
    rowsStore.push(...newRows);
    renderTableRows(newRows);
    showAlert("SET OK", "success");
  }

  // ====== Live dummy polling (untuk DUMMY_MODE=True) ======
  async function pollDummyOnce() {
    try {
      const payload = {
        operation: "walk",
        ip: "127.0.0.1",
        version: "v2c",
        community: "public",
        oid: "1.3.6.1.4.1.9999.1.2",
      };
      const data = await snmpCall(payload);
      const newRows = (data.rows || []).map((r) => ({
        ...r,
        ts: r.ts || nowISO(),
        source: r.source || "backend",
      }));
      rowsStore.push(...newRows);
      renderTableRows(newRows);

      const byName = Object.fromEntries(
        newRows.map((r) => [r.name, Number(r.value)])
      );
      updateTempHumChart(byName.temperature, byName.humidity);
      updateVoltCurrChart(byName.voltage, byName.current);
    } catch (e) {
      // sudah di-handle snmpCall
    }
  }

  function startLive() {
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(() => {
      if (!liveOn) return;
      // boleh tetap polling meskipun page snmp-table,
      // grafik juga akan ikut keisi saat buka sensor-monitoring
      pollDummyOnce();
    }, 1500);
    $("#toggle-live-btn")?.classList.remove("btn-3");
    $("#toggle-live-btn")?.classList.add("btn-2");
    if ($("#toggle-live-btn")) $("#toggle-live-btn").textContent = "Pause Live";
    $("#live-badge")?.classList.remove("hidden");
  }

  function stopLive() {
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
    $("#toggle-live-btn")?.classList.remove("btn-2");
    $("#toggle-live-btn")?.classList.add("btn-3");
    if ($("#toggle-live-btn")) $("#toggle-live-btn").textContent = "Resume Live";
    $("#live-badge")?.classList.add("hidden");
  }

  function toggleLive() {
    liveOn = !liveOn;
    if (liveOn) {
      startLive();
      showAlert("Live ON", "success");
    } else {
      stopLive();
      showAlert("Live OFF", "warning");
    }
  }

  // ====== MIB Browser Placeholder ======
  async function resolveMib() {
    const q = $("#mib-query")?.value?.trim();
    if (!q) return showAlert("Isi OID/MIB dulu", "warning");
    // Untuk real MIB lookup berdasarkan MIB lokal, perlu endpoint backend tambahan.
    // Sementara: langsung GET ke oid tsb (GET)
    $("#oid").value = q;
    await runOp("get");
  }

  async function browseMib() {
    const q = $("#mib-query")?.value?.trim() || $("#oid")?.value?.trim();
    if (!q) return showAlert("Isi OID/MIB dulu", "warning");
    $("#oid").value = q;
    await runOp("walk");
  }

  // ====== Expose ke global agar onclick HTML bisa pakai ======
  window.showPage = showPage;
  window.runOp = runOp;
  window.doSet = doSet;
  window.toggleLive = toggleLive;
  window.clearTable = clearTable;
  window.exportCSV = exportCSV;
  window.ensureCharts = ensureCharts;
  window.updateTempHumChart = updateTempHumChart;
  window.updateVoltCurrChart = updateVoltCurrChart;
  window.resolveMib = resolveMib;
  window.browseMib = browseMib;

  // ====== Init ======
  document.addEventListener("DOMContentLoaded", () => {
    // default page
    showPage("snmp-table");
    ensureCharts();
    startLive();
    log("Frontend ready. Backend:", BACKEND);
  });
})();
