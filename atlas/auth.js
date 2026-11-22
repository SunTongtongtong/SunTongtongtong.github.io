// 登录门禁：每个页面在 <head> 里引入。账号表在 users.js（window.ATLAS_USERS），由 users.py 生成。
// 注意：纯静态站点上的前端门禁，只能挡住随手访问，不是真正的访问控制；只放公开数据。
(function () {
  const KEY = "atlas_auth";
  const TTL_DAYS = 14;
  const root = document.currentScript.getAttribute("data-root") || "./";
  const loginPage = root + "login.html";
  const isLogin = /\/login\.html$/.test(location.pathname);

  function read() {
    try { return JSON.parse(localStorage.getItem(KEY) || "null"); } catch (e) { return null; }
  }
  function valid(s) {
    const db = window.ATLAS_USERS && window.ATLAS_USERS.users;
    return !!(s && db && db[s.u] && db[s.u].hash === s.h && s.t > Date.now());
  }

  // PBKDF2-SHA256，与 users.py 一致
  async function pbkdf2(pw, saltHex, iter) {
    const salt = new Uint8Array(saltHex.match(/../g).map(h => parseInt(h, 16)));
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(pw), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: iter }, key, 256);
    return [...new Uint8Array(bits)].map(b => b.toString(16).padStart(2, "0")).join("");
  }

  window.atlasLogin = async function (user, pw) {
    const cfg = window.ATLAS_USERS, rec = cfg && cfg.users[user];
    if (!rec) return false;
    const h = await pbkdf2(pw, rec.salt, cfg.iter);
    if (h !== rec.hash) return false;
    try { localStorage.setItem(KEY, JSON.stringify({ u: user, h, t: Date.now() + TTL_DAYS * 864e5 })); } catch (e) {}
    return true;
  };
  window.atlasLogout = function () {
    try { localStorage.removeItem(KEY); } catch (e) {}
    location.href = loginPage;
  };
  window.atlasUser = function () { const s = read(); return valid(s) ? s.u : null; };

  if (isLogin) return;
  // 未登录：先隐藏页面，跳到登录页并带上回跳地址
  if (!valid(read())) {
    document.documentElement.style.visibility = "hidden";
    location.replace(loginPage + "?next=" + encodeURIComponent(location.pathname + location.search + location.hash));
  }
})();
