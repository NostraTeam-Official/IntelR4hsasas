(() => {
  "use strict";

  const API_BASE = String(window.INTELR4H_API || "http://127.0.0.1:8000").replace(/\/$/, "");
  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));
  const state = { token: sessionStorage.getItem("intelr4h_token"), user: null, authMode: "login", page: "overview", toastTimer: null };

  const roleNames = { owner: "Kurucu", admin: "Yönetici", user: "Normal kullanıcı" };
  const pageNames = { overview: "GENEL BAKIŞ", search: "KAYIT SORGULA", records: "KAYIT YÖNETİMİ", users: "KULLANICILAR", stats: "CANLI İSTATİSTİK" };

  function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, (char) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    })[char]);
  }

  function formatDate(value, withTime = true) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "—";
    return new Intl.DateTimeFormat("tr-TR", withTime
      ? { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" }
      : { day: "2-digit", month: "long", year: "numeric" }).format(date);
  }

  function remainingTime(value) {
    if (!value) return "Henüz gerekli değil";
    const diff = new Date(value).getTime() - Date.now();
    if (diff <= 0) return "Yenilenmeye hazır";
    const hours = Math.ceil(diff / 3600000);
    if (hours < 24) return `${hours} saat sonra`;
    return `${Math.ceil(hours / 24)} gün sonra`;
  }

  function detailMessage(detail) {
    if (typeof detail === "string") return detail;
    if (detail && typeof detail === "object") return detail.message || detail.detail || detail.error || "İşlem tamamlanamadı.";
    return "İşlem tamamlanamadı.";
  }

  async function api(path, options = {}) {
    const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
    if (state.token) headers.Authorization = `Bearer ${state.token}`;
    let response;
    try {
      response = await fetch(`${API_BASE}${path}`, { ...options, headers, cache: "no-store" });
    } catch (_error) {
      throw new Error("API bağlantısı kurulamadı. Python sunucusunu ve API adresini kontrol et.");
    }
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      if (response.status === 401 && state.token && !["/api/login", "/api/register"].includes(path)) {
        signOut(false);
        throw new Error("Oturumun sona erdi. Tekrar giriş yap.");
      }
      throw new Error(detailMessage(data.detail || data.message));
    }
    return data;
  }

  function showMessage(target, text, type = "info") {
    const element = typeof target === "string" ? $(target) : target;
    if (!element) return;
    element.textContent = text;
    element.className = `message show ${type}`;
  }

  function clearMessage(target) {
    const element = typeof target === "string" ? $(target) : target;
    if (!element) return;
    element.textContent = "";
    element.className = "message";
  }

  function toast(message, type = "success") {
    const element = $("#toast");
    element.textContent = message;
    element.className = `toast visible ${type}`;
    window.clearTimeout(state.toastTimer);
    state.toastTimer = window.setTimeout(() => { element.className = "toast"; }, 3500);
  }

  function updateRoleUi() {
    if (!state.user) return;
    const initials = (state.user.email || "IR").slice(0, 2).toUpperCase();
    $("#userAvatar").textContent = initials;
    $("#topbarAvatar").textContent = initials;
    $("#sidebarEmail").textContent = state.user.email;
    $("#sidebarRole").textContent = roleNames[state.user.role] || roleNames.user;
    $("#planLabel").textContent = state.user.role === "owner" ? "FOUNDER PLAN" : state.user.role === "admin" ? "ADMIN PLAN" : "NORMAL PLAN";
    $("#welcomeEmail").textContent = state.user.email;
    $$(".admin-only").forEach((item) => item.classList.toggle("hidden", !["owner", "admin"].includes(state.user.role)));
    $$(".owner-only").forEach((item) => item.classList.toggle("hidden", state.user.role !== "owner"));
  }

  function setAuthMode(mode) {
    state.authMode = mode;
    const registering = mode === "register";
    $$("[data-auth-mode]").forEach((button) => {
      const active = button.dataset.authMode === mode;
      button.classList.toggle("active", active);
      button.setAttribute("aria-selected", String(active));
    });
    $("#authHeading").textContent = registering ? "Yeni hesap oluştur." : "Tekrar hoş geldin.";
    $("#authSubtitle").textContent = registering ? "Kişisel erişimini birkaç adımda hazırla." : "Kontrol paneline erişmek için giriş yap.";
    $("#authSubmit span:first-child").textContent = registering ? "Hesap oluştur" : "Giriş yap";
    $("#authPassword").autocomplete = registering ? "new-password" : "current-password";
    $("#authPassword").placeholder = registering ? "En az 10 karakter" : "Parolan";
    $("#setupCodeGroup").classList.toggle("hidden", !registering);
    clearMessage("#authMessage");
  }

  async function onAuthSubmit(event) {
    event.preventDefault();
    clearMessage("#authMessage");
    const button = $("#authSubmit");
    const email = $("#authEmail").value.trim();
    const password = $("#authPassword").value;
    const payload = { email, password };
    if (state.authMode === "register") {
      payload.setup_code = $("#setupCode").value.trim() || null;
      if (password.length < 10) {
        showMessage("#authMessage", "Parolan en az 10 karakter olmalı.", "error");
        return;
      }
    }
    button.disabled = true;
    button.classList.add("loading");
    $("#authSubmit span:first-child").textContent = "Kontrol ediliyor...";
    try {
      const result = await api(state.authMode === "register" ? "/api/register" : "/api/login", {
        method: "POST", body: JSON.stringify(payload), headers: {}
      });
      state.token = result.token;
      state.user = result.user;
      sessionStorage.setItem("intelr4h_token", result.token);
      await showApplication();
      toast(state.authMode === "register" ? "Hesabın oluşturuldu." : "Giriş başarılı.");
    } catch (error) {
      showMessage("#authMessage", error.message, "error");
    } finally {
      button.disabled = false;
      button.classList.remove("loading");
      $("#authSubmit span:first-child").textContent = state.authMode === "register" ? "Hesap oluştur" : "Giriş yap";
    }
  }

  async function showApplication() {
    const result = await api("/api/me");
    state.user = result.user;
    $("#authView").classList.add("hidden");
    $("#appView").classList.remove("hidden");
    updateRoleUi();
    $("#todayDate").textContent = new Intl.DateTimeFormat("tr-TR", { weekday: "short", day: "2-digit", month: "short" }).format(new Date());
    await Promise.allSettled([loadStats(), loadQuota()]);
    navigate("overview");
    window.clearInterval(window.intelr4hRefresh);
    window.intelr4hRefresh = window.setInterval(() => {
      loadStats();
      loadQuota();
    }, 30000);
  }

  function signOut(showToast = true) {
    state.token = null;
    state.user = null;
    sessionStorage.removeItem("intelr4h_token");
    window.clearInterval(window.intelr4hRefresh);
    $("#appView").classList.add("hidden");
    $("#authView").classList.remove("hidden");
    $("#authPassword").value = "";
    $("#setupCode").value = "";
    setAuthMode("login");
    if (showToast) toast("Oturum kapatıldı.");
  }

  function navigate(page) {
    if (page === "records" && !["owner", "admin"].includes(state.user?.role)) page = "overview";
    if (page === "users" && state.user?.role !== "owner") page = "overview";
    state.page = page;
    $$(".page-section").forEach((section) => section.classList.toggle("hidden", section.id !== `page-${page}`));
    $$(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.page === page));
    $("#pageBreadcrumb").textContent = pageNames[page] || pageNames.overview;
    $("#sidebar").classList.remove("sidebar-open");
    if (page === "records") loadRecords();
    if (page === "users") loadUsers();
    if (page === "stats") loadStats();
    if (page === "search") loadQuota();
  }

  async function loadStats() {
    try {
      const stats = await api("/api/stats");
      $("#overviewActive").textContent = stats.active_users;
      $("#overviewUsers").textContent = stats.registered_users;
      $("#overviewRecords").textContent = stats.saved_records;
      $("#overviewSearches").textContent = stats.searches_24h;
      $("#statsActiveLarge").textContent = stats.active_users;
      $("#statsUsers").textContent = stats.registered_users;
      $("#statsRecords").textContent = stats.saved_records;
      $("#statsSearches").textContent = stats.searches_24h;
      $("#connectionLabel").textContent = `API bağlı · ${new Date().toLocaleTimeString("tr-TR", { hour: "2-digit", minute: "2-digit" })}`;
    } catch (error) {
      $("#connectionLabel").textContent = "API bağlantısı yok";
      $("#connectionLabel").parentElement.classList.add("connection-error");
    }
  }

  function applyQuota(quota) {
    const used = Math.min(Number(quota.used || 0), 5);
    const remaining = Math.max(0, Number(quota.remaining ?? (5 - used)));
    const percent = `${(used / 5) * 100}%`;
    $("#planQuota").textContent = `${remaining} / 5 sorgu kaldı`;
    $("#sidebarQuotaText").textContent = `${used} kullanıldı · 72 saatlik kota`;
    $("#sidebarQuotaBar").style.width = percent;
    $("#overviewRemaining").textContent = `${remaining} / 5`;
    $("#overviewQuotaBar").style.width = percent;
    $("#searchQuotaBar").style.width = percent;
    $("#searchQuotaDisplay").textContent = `${remaining} / 5`;
    $("#searchAsideRemaining").textContent = String(remaining).padStart(2, "0");
    $("#searchQuotaHelp").textContent = remaining > 0 ? `72 saatlik pencerede ${remaining} sorgu hakkın kaldı.` : "Kota doldu. Bir sorgu hakkı açılana kadar bekle.";
    $("#searchPlanName").textContent = state.user?.role === "owner" ? "Kurucu" : state.user?.role === "admin" ? "Yönetici" : "Normal";
    $("#overviewPlan").textContent = `${roleNames[state.user?.role] || "Normal kullanıcı"} · 72 saat`;
    $("#quotaUsedText").textContent = used ? `${used} sorgu kullanıldı` : "Henüz sorgu kullanılmadı";
    $("#searchResetAt").textContent = quota.reset_at ? remainingTime(quota.reset_at) : "Gerekli değil";
    $("#searchButton").disabled = remaining <= 0;
    $("#searchButton").classList.toggle("disabled-button", remaining <= 0);
  }

  async function loadQuota() {
    if (!state.token) return;
    try {
      const quota = await api("/api/quota");
      applyQuota(quota);
    } catch (_error) {
      // Connection status is already shown in the top bar.
    }
  }

  async function onSearch(event) {
    event.preventDefault();
    clearMessage("#searchMessage");
    const discordId = $("#discordIdInput").value.trim();
    if (!/^\d{5,25}$/.test(discordId)) {
      showMessage("#searchMessage", "5–25 rakamdan oluşan bir Discord ID gir.", "error");
      return;
    }
    const button = $("#searchButton");
    button.disabled = true;
    button.classList.add("loading");
    button.querySelector("span:first-child").textContent = "Aranıyor...";
    $("#resultStatus").textContent = "SORGULANIYOR";
    $("#resultStatus").className = "result-tag pending";
    $("#searchResult").innerHTML = '<div class="empty-result-icon spin-icon">◌</div><strong>Kayıtlar kontrol ediliyor</strong><p>Yalnızca dahili kayıtlar taranıyor.</p>';
    try {
      const result = await api("/api/search", { method: "POST", body: JSON.stringify({ discord_id: discordId }) });
      applyQuota(result.quota);
      if (result.found && result.record) {
        const record = result.record;
        $("#resultStatus").textContent = "KAYIT BULUNDU";
        $("#resultStatus").className = "result-tag found";
        $("#searchResult").innerHTML = `
          <div class="record-result">
            <div class="record-result-top"><div class="record-avatar">${escapeHtml((record.username || "ID").slice(0, 2).toUpperCase())}</div><div class="record-result-name"><strong>${escapeHtml(record.username || "İsimsiz kayıt")}</strong><small>Discord ID: ${escapeHtml(record.discord_id)}</small></div><span class="result-tag found">DAHİLİ KAYIT</span></div>
            <div class="result-fields"><div class="result-field"><span>Etiketler</span><strong>${escapeHtml(record.tags || "Etiket yok")}</strong></div><div class="result-field"><span>Kayıt tarihi</span><strong>${escapeHtml(formatDate(record.created_at))}</strong></div></div>
            <div class="record-note"><span>İZİNLİ NOT</span><p>${escapeHtml(record.approved_summary || "Bu kayıt için ek not bulunmuyor.")}</p></div>
            <div class="record-source"><span>Kaynak / yetki notu</span><p>${escapeHtml(record.source_note || "Belirtilmemiş")}</p></div>
          </div>`;
      } else {
        $("#resultStatus").textContent = "KAYIT YOK";
        $("#resultStatus").className = "result-tag not-found";
        $("#searchResult").innerHTML = '<div class="empty-result-icon">⌕</div><strong>Dahili kayıt bulunamadı</strong><p>Bu ID için IntelR4h veritabanında kayıt yok. Harici veya sızdırılmış veri aranmadı.</p>';
      }
      showMessage("#searchMessage", "Sorgu tamamlandı. Bir arama hakkı kullanıldı.", "success");
    } catch (error) {
      $("#resultStatus").textContent = "TAMAMLANAMADI";
      $("#resultStatus").className = "result-tag not-found";
      showMessage("#searchMessage", error.message, "error");
      if (error.message.toLowerCase().includes("kota") || error.message.toLowerCase().includes("72 saat")) {
        $("#searchResult").innerHTML = '<div class="empty-result-icon">◷</div><strong>Sorgu kotası doldu</strong><p>72 saatlik pencerede bir sorgu hakkı açılınca tekrar deneyebilirsin.</p>';
        await loadQuota();
      } else {
        $("#searchResult").innerHTML = '<div class="empty-result-icon">!</div><strong>Sorgu yapılamadı</strong><p>Mesajı kontrol et ve tekrar dene.</p>';
      }
    } finally {
      button.classList.remove("loading");
      button.querySelector("span:first-child").textContent = "Sorgula";
      await loadQuota();
      button.disabled = Number($("#searchAsideRemaining").textContent) <= 0;
    }
  }

  async function loadRecords() {
    const container = $("#recordList");
    container.innerHTML = '<div class="loading-line">Kayıtlar yükleniyor...</div>';
    try {
      const result = await api("/api/records");
      if (!result.records.length) {
        container.innerHTML = '<div class="list-empty"><span>▤</span><strong>Henüz kayıt yok</strong><p>İlk izinli dahili kaydı yukarıdaki formdan ekleyebilirsin.</p></div>';
        return;
      }
      container.innerHTML = result.records.map((record) => `
        <article class="record-list-item"><div class="record-list-avatar">${escapeHtml((record.username || "ID").slice(0, 2).toUpperCase())}</div><div class="record-list-info"><strong>${escapeHtml(record.username || "İsimsiz kayıt")}</strong><small>${escapeHtml(record.discord_id)}${record.tags ? ` · ${escapeHtml(record.tags)}` : ""}</small><p>${escapeHtml(record.approved_summary || "Ek not yok")}</p></div><span class="record-list-date">${escapeHtml(formatDate(record.created_at))}</span></article>`).join("");
    } catch (error) {
      container.innerHTML = `<div class="list-empty"><strong>Kayıtlar yüklenemedi</strong><p>${escapeHtml(error.message)}</p></div>`;
    }
  }

  async function onRecordSubmit(event) {
    event.preventDefault();
    clearMessage("#recordMessage");
    if (!$("#recordConsent").checked) {
      showMessage("#recordMessage", "Kaydı eklemek için yetkin olduğunu onaylamalısın.", "error");
      return;
    }
    const payload = {
      discord_id: $("#recordDiscordId").value.trim(),
      username: $("#recordUsername").value.trim(),
      tags: $("#recordTags").value.trim(),
      approved_summary: $("#recordSummary").value.trim(),
      source_note: $("#recordSource").value.trim()
    };
    try {
      await api("/api/records", { method: "POST", body: JSON.stringify(payload) });
      $("#recordForm").reset();
      showMessage("#recordMessage", "Kayıt güvenli şekilde eklendi.", "success");
      toast("Dahili kayıt eklendi.");
      await Promise.all([loadRecords(), loadStats()]);
    } catch (error) {
      showMessage("#recordMessage", error.message, "error");
    }
  }

  async function loadUsers() {
    const container = $("#usersList");
    container.innerHTML = '<div class="loading-line">Kullanıcılar yükleniyor...</div>';
    try {
      const result = await api("/api/users");
      if (!result.users.length) {
        container.innerHTML = '<div class="list-empty"><strong>Kullanıcı bulunamadı</strong></div>';
        return;
      }
      const canManage = state.user?.role === "owner";
      container.innerHTML = `<table class="users-table"><thead><tr><th>HESAP</th><th>ROL</th><th>OLUŞTURULMA</th><th>SON AKTİFLİK</th>${canManage ? "<th>İŞLEM</th>" : ""}</tr></thead><tbody>${result.users.map((user) => {
        let roleMarkup = `<span class="role-pill role-${escapeHtml(user.role)}">${escapeHtml(roleNames[user.role] || user.role)}</span>`;
        let actionMarkup = "";
        if (canManage && user.role !== "owner") {
          const nextRole = user.role === "admin" ? "user" : "admin";
          const label = nextRole === "admin" ? "Yönetici yap" : "Yetkiyi kaldır";
          actionMarkup = `<td><button class="btn-mini ${nextRole === "admin" ? "mini-primary" : "mini-quiet"}" data-user-id="${user.id}" data-next-role="${nextRole}">${label}</button></td>`;
        } else if (canManage) {
          actionMarkup = '<td><span class="protected-label">KORUNUYOR</span></td>';
        }
        return `<tr><td><div class="table-user"><span class="table-avatar">${escapeHtml(user.email.slice(0, 2).toUpperCase())}</span><div><strong>${escapeHtml(user.email)}</strong><small>#${user.id}</small></div></div></td><td>${roleMarkup}</td><td>${escapeHtml(formatDate(user.created_at))}</td><td><span class="activity-dot ${user.active ? "online" : "offline"}"></span>${escapeHtml(user.active ? "Aktif" : formatDate(user.last_seen))}</td>${actionMarkup}</tr>`;
      }).join("")}</tbody></table>`;
    } catch (error) {
      container.innerHTML = `<div class="list-empty"><strong>Kullanıcı listesi alınamadı</strong><p>${escapeHtml(error.message)}</p></div>`;
    }
  }

  async function changeRole(userId, role) {
    const action = role === "admin" ? "yönetici yapmak" : "yönetici yetkisini kaldırmak";
    if (!window.confirm(`Bu hesabın rolünü değiştirmek istediğine emin misin?`)) return;
    clearMessage("#usersMessage");
    try {
      await api("/api/admin/role", { method: "POST", body: JSON.stringify({ user_id: Number(userId), role }) });
      showMessage("#usersMessage", `Hesap rolü güncellendi: ${action}.`, "success");
      await loadUsers();
      await loadStats();
    } catch (error) {
      showMessage("#usersMessage", error.message, "error");
    }
  }

  function bindEvents() {
    $$("[data-auth-mode]").forEach((button) => button.addEventListener("click", () => setAuthMode(button.dataset.authMode)));
    $("#authForm").addEventListener("submit", onAuthSubmit);
    $("#togglePassword").addEventListener("click", () => {
      const input = $("#authPassword");
      const show = input.type === "password";
      input.type = show ? "text" : "password";
      $("#togglePassword").textContent = show ? "Gizle" : "Göster";
    });
    $("#logoutBtn").addEventListener("click", () => signOut(true));
    $$("[data-page]").forEach((button) => button.addEventListener("click", () => navigate(button.dataset.page)));
    $$("[data-go]").forEach((button) => button.addEventListener("click", () => navigate(button.dataset.go)));
    $("#searchForm").addEventListener("submit", onSearch);
    $("#recordForm").addEventListener("submit", onRecordSubmit);
    $("#refreshRecords").addEventListener("click", loadRecords);
    $("#refreshUsers").addEventListener("click", loadUsers);
    $("#usersList").addEventListener("click", (event) => {
      const button = event.target.closest("[data-user-id]");
      if (button) changeRole(button.dataset.userId, button.dataset.nextRole);
    });
    $("#openSidebar").addEventListener("click", () => $("#sidebar").classList.add("sidebar-open"));
    $("#closeSidebar").addEventListener("click", () => $("#sidebar").classList.remove("sidebar-open"));
  }

  async function boot() {
    bindEvents();
    setAuthMode("login");
    if (!state.token) return;
    try {
      await showApplication();
    } catch (_error) {
      signOut(false);
    }
  }

  document.addEventListener("DOMContentLoaded", boot);
})();
