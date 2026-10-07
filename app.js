/* ═══════════════════════════════════════════════════════════════════
   نظام مبيعات صيدلية درب الشفاء — النواة البرمجية الكاملة
   البنية: Offline-First (IndexedDB) + مزامنة Firebase + أرشفة ذكية
   ═══════════════════════════════════════════════════════════════════ */
'use strict';

/* ───────────────────────── 1) أدوات عامة ───────────────────────── */
const $  = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];
const uid = () => (crypto.randomUUID ? crypto.randomUUID() : `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 12)}-${Math.random().toString(36).slice(2, 12)}`);
const DEVICE_ID = (() => { let d = localStorage.getItem('ds_device'); if (!d) { d = uid(); localStorage.setItem('ds_device', d); } return d; })();

function h(tag, attrs = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'html') el.innerHTML = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'dataset') Object.assign(el.dataset, v);
    else if (k === 'style' && typeof v === 'object') Object.assign(el.style, v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (let kid of kids.flat(Infinity)) {
    if (kid == null || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(kid));
  }
  return el;
}
const fmt  = n => (Math.round((+n || 0) * 100) / 100).toLocaleString('en-US');
const num  = v => { const n = parseFloat(v); return isNaN(n) ? 0 : n; };
const DAYS = ['الأحد','الاثنين','الثلاثاء','الأربعاء','الخميس','الجمعة','السبت'];
const pad2 = n => String(n).padStart(2, '0');
function dateStr(ts = Date.now()) { const d = new Date(ts); return `${d.getFullYear()}-${pad2(d.getMonth()+1)}-${pad2(d.getDate())}`; }
function timeStr(ts = Date.now()) { const d = new Date(ts); return `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`; }
function fmtDate(ts) { if (!ts) return '—'; const d = new Date(ts); return `${pad2(d.getDate())}/${pad2(d.getMonth()+1)}/${d.getFullYear()}`; }
function fmtTime(ts) { return ts ? timeStr(ts).slice(0,5) : '—'; }
function dayName(ts = Date.now()) { return DAYS[new Date(ts).getDay()]; }
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const cur = () => state.settings.currency || 'د.ع';
/* شارة الشركة المصنعة — تلاصق اسم البراند كنص واحد أينما عُرض */
const coTag = p => p && p.company ? h('small', { style: { display: 'inline', marginInlineStart: '7px', color: 'var(--blue)', fontWeight: 800, fontSize: '11px' } }, p.company) : null;

/* ───────────────────────── 1-ب) الأمن: PBKDF2 + حارس التخمين + صور آمنة ───────────────────────── */
const PBKDF2_ITER = 150000; // قوة التجزئة — ارفعها إلى 250000 إن كانت أجهزتك حديثة
const _b64e = b => btoa(String.fromCharCode(...new Uint8Array(b)));
const _b64d = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
async function pbkdf2(pass, saltB64, iter = PBKDF2_ITER) {
  const k = await crypto.subtle.importKey('raw', new TextEncoder().encode(String(pass)), 'PBKDF2', false, ['deriveBits']);
  return _b64e(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: _b64d(saltB64), iterations: iter }, k, 256));
}
async function setPassword(acc, pass) { // يخزّن بصمة + ملحاً عشوائياً فقط — لا نص صريح أبداً
  acc.passSalt = _b64e(crypto.getRandomValues(new Uint8Array(16)));
  acc.passIter = PBKDF2_ITER;
  acc.passHash = await pbkdf2(pass, acc.passSalt, acc.passIter);
  delete acc.password;
  acc.mustChangePass = false;
}
async function verifyPassword(acc, pass) {
  if (acc.passHash) return (await pbkdf2(pass, acc.passSalt, acc.passIter || PBKDF2_ITER)) === acc.passHash;
  if (acc.password != null) { // حساب قديم بنص صريح: تحقق ثم ترحيل فوري للبصمة
    if (String(pass) !== String(acc.password)) return false;
    await setPassword(acc, pass);
    await save('accounts', acc);
    return true;
  }
  return false;
}
/* حارس التخمين: 5 محاولات فاشلة → قفل مؤقت يتضاعف (30ث ثم 60ث ثم 120ث… بحد أقصى 10 دقائق) */
const loginGuard = {};
const guardWait = id => { const g = loginGuard[id]; return g && g.lockUntil > Date.now() ? Math.ceil((g.lockUntil - Date.now()) / 1000) : 0; };
function guardFail(id) {
  const g = loginGuard[id] = loginGuard[id] || { fails: 0, lockUntil: 0 };
  g.fails++;
  if (g.fails >= 5) g.lockUntil = Date.now() + Math.min(600, 30 * 2 ** (g.fails - 5)) * 1000;
  return guardWait(id);
}
const guardOK = id => { delete loginGuard[id]; };
/* صورة الحساب تُبنى عبر DOM وتُقبل فقط إن كانت data:image حقيقية — يقفل ثغرة XSS في acc.photo */
const SAFE_PHOTO = /^data:image\/(png|jpe?g|webp|gif);base64,[A-Za-z0-9+/=\s]+$/i;
function avatarNode(acc) {
  const w = document.createElement('span');
  w.style.cssText = 'display:inline-flex;width:100%;height:100%;border-radius:50%;overflow:hidden;align-items:center;justify-content:center;flex:none';
  if (acc && acc.photo && SAFE_PHOTO.test(acc.photo) && acc.photo.length <= 4 * 1024 * 1024) {
    const img = document.createElement('img');
    img.alt = ''; img.draggable = false; img.style.cssText = 'width:100%;height:100%;object-fit:cover';
    img.src = acc.photo; w.append(img);
  } else w.innerHTML = avatarSVG(acc && acc.gender); // SVG ثابت من كودنا — لا بيانات مستخدم فيه
  return w;
}
function readAvatarFile(fileInp, cb) { // تحقق موحّد لصور الحسابات المرفوعة
  const f = fileInp.files[0]; if (!f) return;
  if (!/^image\/(png|jpe?g|webp|gif)$/i.test(f.type)) return toast('اختر ملف صورة فقط (PNG / JPG / WebP)', 'r');
  if (f.size > 2.5 * 1024 * 1024) return toast('الصورة كبيرة — الحد الأقصى 2.5MB', 'r');
  const r = new FileReader();
  r.onload = () => cb(r.result);
  r.readAsDataURL(f);
}

/* ───────────────────────── 2) الأيقونات SVG ───────────────────────── */
const IC = (p, vb='0 0 24 24') => `<svg class="ic" viewBox="${vb}" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${p}</svg>`;
const ICONS = {
  pos:      IC('<circle cx="9" cy="21" r="1.6"/><circle cx="19" cy="21" r="1.6"/><path d="M2.5 3h2l2.6 12.4a2 2 0 0 0 2 1.6h9.7a2 2 0 0 0 2-1.6L22.5 7H6"/>'),
  report:   IC('<path d="M3 3v18h18"/><path d="M7 15l4-5 3.5 3.5L19 8"/><circle cx="19" cy="8" r="1.4" fill="currentColor"/>'),
  store:    IC('<path d="M21 8l-9-5-9 5v8l9 5 9-5z"/><path d="M3.5 8.5L12 13l8.5-4.5M12 13v8"/>'),
  purchase: IC('<path d="M1.5 4h13v12h-13z"/><path d="M14.5 8h4l3.5 4v4h-8"/><circle cx="6" cy="18.5" r="1.8"/><circle cx="17.5" cy="18.5" r="1.8"/>'),
  suppliers:IC('<circle cx="9" cy="8" r="3.4"/><path d="M2.5 20c.7-3.6 3.4-5.5 6.5-5.5s5.8 1.9 6.5 5.5"/><circle cx="17.5" cy="9.5" r="2.6"/><path d="M16 14.6c2.9.3 5 2.1 5.5 5.4"/>'),
  settings: IC('<circle cx="12" cy="12" r="3.2"/><path d="M19.4 15a1.7 1.7 0 0 0 .34 1.87l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.7 1.7 0 0 0-1.87-.34 1.7 1.7 0 0 0-1 1.55V21a2 2 0 1 1-4 0v-.09a1.7 1.7 0 0 0-1-1.55 1.7 1.7 0 0 0-1.87.34l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.7 1.7 0 0 0 .34-1.87 1.7 1.7 0 0 0-1.55-1H3a2 2 0 1 1 0-4h.09a1.7 1.7 0 0 0 1.55-1 1.7 1.7 0 0 0-.34-1.87l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.7 1.7 0 0 0 1.87.34h.09a1.7 1.7 0 0 0 1-1.55V3a2 2 0 1 1 4 0v.09a1.7 1.7 0 0 0 1 1.55h.09a1.7 1.7 0 0 0 1.87-.34l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.7 1.7 0 0 0-.34 1.87v.09a1.7 1.7 0 0 0 1.55 1H21a2 2 0 1 1 0 4h-.09a1.7 1.7 0 0 0-1.55 1z"/>'),
  plus:     IC('<path d="M12 5v14M5 12h14"/>'),
  search:   IC('<circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/>'),
  edit:     IC('<path d="M17 3a2.8 2.8 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5z"/>'),
  trash:    IC('<path d="M3 6h18M8 6V4a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2m3 0v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/>'),
  eye:      IC('<path d="M1.5 12S5.5 4.5 12 4.5 22.5 12 22.5 12 18.5 19.5 12 19.5 1.5 12 1.5 12z"/><circle cx="12" cy="12" r="3"/>'),
  dollar:   IC('<circle cx="12" cy="12" r="9.5"/><path d="M12 6.5v11M15.5 9c-.7-1-1.9-1.5-3.5-1.5-2 0-3.2 1-3.2 2.5 0 3.5 7 1.7 7 5 0 1.6-1.4 2.5-3.5 2.5-1.8 0-3.1-.7-3.8-1.8"/>'),
  pill:     IC('<rect x="3" y="9" width="18" height="7" rx="3.5" transform="rotate(-45 12 12)"/><path d="M8.5 8.5l7 7"/>'),
  close:    IC('<path d="M18 6L6 18M6 6l12 12"/>'),
  user:     IC('<circle cx="12" cy="8" r="4"/><path d="M4 21c.9-4.4 4.2-6.5 8-6.5s7.1 2.1 8 6.5"/>'),
  logout:   IC('<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="M16 17l5-5-5-5M21 12H9"/>'),
  check:    IC('<path d="M20 6L9 17l-5-5"/>'),
  warn:     IC('<path d="M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4M12 17h.01"/>'),
  camera:   IC('<path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="4"/>'),
  cash:     IC('<rect x="2" y="6" width="20" height="12" rx="2"/><circle cx="12" cy="12" r="2.6"/><path d="M6 12h.01M18 12h.01"/>'),
  card:     IC('<rect x="2" y="5" width="20" height="14" rx="2.5"/><path d="M2 10h20M6 15h4"/>'),
  clock:    IC('<circle cx="12" cy="12" r="9.5"/><path d="M12 7v5l3.5 2"/>'),
  box:      IC('<path d="M21 8l-9-5-9 5v8l9 5 9-5z"/><path d="M3.5 8.5L12 13l8.5-4.5M12 13v8"/>'),
  star:     IC('<path d="M12 2.5l2.9 6 6.6.9-4.8 4.6 1.2 6.5L12 17.4 6.1 20.5l1.2-6.5L2.5 9.4l6.6-.9z"/>'),
  barcode:  IC('<path d="M3 5v14M7 5v14M10 5v14M13 5v10M16 5v14M19 5v10M21 5v14"/>'),
  refresh:  IC('<path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.5 9a9 9 0 0 1 14.9-3.4L23 10M1 14l4.6 4.4A9 9 0 0 0 20.5 15"/>'),
  download: IC('<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3"/>'),
  upload:   IC('<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M17 8l-5-5-5 5M12 3v12"/>'),
  lock:     IC('<rect x="4" y="11" width="16" height="10" rx="2.5"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>'),
  history:  IC('<path d="M3 3v5h5"/><path d="M3.05 13a9 9 0 1 0 .5-5L3 8"/><path d="M12 7v5l3.5 2"/>'),
  receipt:  IC('<path d="M5 2h14v20l-2.3-1.5L14.4 22l-2.4-1.5L9.6 22l-2.3-1.5L5 22z"/><path d="M9 7h6M9 11h6M9 15h4"/>'),
  users:    IC('<circle cx="9" cy="8" r="3.4"/><path d="M2.5 20c.7-3.6 3.4-5.5 6.5-5.5s5.8 1.9 6.5 5.5"/><circle cx="17.5" cy="9.5" r="2.6"/><path d="M16 14.6c2.9.3 5 2.1 5.5 5.4"/>'),
};
const icon = n => ICONS[n] || ICONS.box;

/* ───────────────────────── 3) قاعدة البيانات المحلية (IndexedDB) ─────────────────────────
   صخرة صلبة: كل عملية تُحفظ محلياً فوراً قبل أي شيء، والمزامنة لاحقاً.
   معرفات فريدة عالمياً تمنع أي تعارض حتى مع بيع متزامن من جهازين.      */
const DB = (() => {
  const NAME = 'darb_alshifa_db', VER = 3; // v3: + جدول outbox (طابور الرفع المؤجل)
  const STORES = ['accounts','products','sales','purchases','suppliers','payments','customers','settings','meta','outbox'];
  let db = null;
  const wrap = req => new Promise((res, rej) => { req.onsuccess = () => res(req.result); req.onerror = () => rej(req.error); });
  function open() {
    return new Promise((res, rej) => {
      const r = indexedDB.open(NAME, VER);
      r.onupgradeneeded = e => {
        const d = e.target.result;
        STORES.forEach(s => { if (!d.objectStoreNames.contains(s)) d.createObjectStore(s, { keyPath: 'id' }); });
      };
      r.onsuccess = () => { db = r.result; res(db); };
      r.onerror = () => rej(r.error);
    });
  }
  const store = (s, m = 'readonly') => db.transaction(s, m).objectStore(s);
  return {
    open,
    put:    (s, v)    => wrap(store(s, 'readwrite').put(v)),
    get:    (s, id)   => wrap(store(s).get(id)),
    all:    (s)       => wrap(store(s).getAll()),
    del:    (s, id)   => wrap(store(s, 'readwrite').delete(id)),
    clear:  (s)       => wrap(store(s, 'readwrite').clear()),
    bulk: async (s, arr) => { for (const v of arr) await wrap(store(s, 'readwrite').put(v)); },
  };
})();

/* ───────────────────────── 4) الحالة المركزية ───────────────────────── */
const state = {
  accounts: [], products: [], sales: [], purchases: [],
  suppliers: [], payments: [], customers: [],
  settings: {}, session: null, customerId: null,
};

/* أشهر 30 شركة أدوية في السوق العراقي — تُزرع تلقائياً وتتعلم الشركات الجديدة */
const DEFAULT_COMPANIES = [
  { name: 'بايونير (Pioneer)', country: 'العراق' },
  { name: 'سامراء (SDI)', country: 'العراق' },
  { name: 'أواميديكا (Awamedica)', country: 'العراق' },
  { name: 'الجزيرة (Al-Jazeera)', country: 'العراق' },
  { name: 'هيكما (Hikma)', country: 'الأردن' },
  { name: 'دار الدواء (Dar Al Dawa)', country: 'الأردن' },
  { name: 'جلفار (Julphar)', country: 'الإمارات' },
  { name: 'سبيماكو (SPIMACO)', country: 'السعودية' },
  { name: 'جمجوم (Jamjoom)', country: 'السعودية' },
  { name: 'تبوك (Tabuk)', country: 'السعودية' },
  { name: 'أمون (Amoun)', country: 'مصر' },
  { name: 'إيبيكو (EPICO)', country: 'مصر' },
  { name: 'فاركو (Pharco)', country: 'مصر' },
  { name: 'بيليم (Bilim)', country: 'تركيا' },
  { name: 'عبدي إبراهيم (Abdi Ibrahim)', country: 'تركيا' },
  { name: 'وورلد ميديسن (World Medicine)', country: 'تركيا' },
  { name: 'نوبل (Nobel)', country: 'تركيا' },
  { name: 'مايكرو لابس (Micro Labs)', country: 'الهند' },
  { name: 'براون آند بيرك (Brown & Burk)', country: 'الهند' },
  { name: 'سيبلاز (Cipla)', country: 'الهند' },
  { name: 'أوروبيندو (Aurobindo)', country: 'الهند' },
  { name: 'صن فارما (Sun Pharma)', country: 'الهند' },
  { name: 'زايدوس (Zydus)', country: 'الهند' },
  { name: 'أجنتا (Ajanta)', country: 'الهند' },
  { name: 'ماكليودز (Macleods)', country: 'الهند' },
  { name: 'استرازينيكا (AstraZeneca)', country: 'بريطانيا' },
  { name: 'جلاكسو (GSK)', country: 'بريطانيا' },
  { name: 'سانوفي (Sanofi)', country: 'فرنسا' },
  { name: 'نوفارتس (Novartis)', country: 'سويسرا' },
  { name: 'باير (Bayer)', country: 'ألمانيا' },
];

const DEFAULT_SETTINGS = {
  id: 'app', pharmacyName: 'صيدلية درب الشفاء', profitPct: 30, lowStock: 10,
    currency: 'د.ع', geminiKey: '', unitNames: ['قطعة','باكيت','شريط','كرتون','علبة','قنينة','أمبول','فيال','كيس','لفافة'],
  generatedBarcode: 0,
};
const findAcc  = id => state.accounts.find(a => a.id === id);
const findProd = id => state.products.find(p => p.id === id && !p.deleted);
const findSup  = id => state.suppliers.find(s => s.id === id);
const findCust = id => state.customers.find(c => c.id === id);
const me = () => findAcc(state.session);

async function save(storeName, obj) {
  obj.updatedAt = Date.now();
  await DB.put(storeName, obj);
  const coll = state[{accounts:'accounts',products:'products',sales:'sales',purchases:'purchases',suppliers:'suppliers',payments:'payments',customers:'customers'}[storeName] || 'settings'];
  if (Array.isArray(coll)) {
    const i = coll.findIndex(x => x.id === obj.id);
    if (i >= 0) coll[i] = obj; else coll.push(obj);
    } else if (storeName === 'settings') state.settings = obj;
  Sync.push(storeName, obj);
  refreshActiveTab(); // تحديث فوري لأي تبويب تقريري مفتوح عند أي حفظ
  return obj;
}

/* ───────────────────────── 5) مزامنة Firebase ─────────────────────────
   تعمل فور وضع إعدادات المشروع في firebase-config.js.
   Firestore Offline Persistence = لا ضياع لأي بيانات حتى مع انقطاع النت.
   المزامنة ثنائية: أي جهازين يبيعان بنفس الثانية تُدمج بياناتهما تلقائياً. */
const Sync = {
  ready: false, fs: null, _listening: false,
  COLLECTIONS: ['accounts','products','sales','purchases','suppliers','payments','customers'],
  async init() {
    if (this.ready) { this.flush(); return; } // إعادة دخول بعد عودة النت: ارفع الطابور فقط
    const cfg = window.FIREBASE_CONFIG;
    if (!cfg || !cfg.apiKey) { setSyncUI(false); return; }
    try {
      if (!window.firebase) { // لا تعِد تحميل SDK إن كان محمَّلاً من محاولة سابقة
        await this.loadScript('https://www.gstatic.com/firebasejs/10.12.2/firebase-app-compat.js');
        await this.loadScript('https://www.gstatic.com/firebasejs/10.12.2/firebase-firestore-compat.js');
      }
      if (!firebase.apps.length) firebase.initializeApp(cfg);
      this.fs = firebase.firestore();
      try { await this.fs.enablePersistence({ synchronizeTabs: true }); } catch (e) { /* متعدد التبويبات أو غير مدعوم */ }
      this.ready = true;
      setSyncUI(true);
      if (!this._listening) { this._listening = true; this.listen(); }
      this.flush(); // ارفع فوراً كل ما تراكم في الـ outbox أثناء الانقطاع
    } catch (e) { console.warn('Firebase sync disabled:', e); setSyncUI(false); }
  },
  loadScript(src) { return new Promise((res, rej) => { const s = document.createElement('script'); s.src = src; s.onload = res; s.onerror = rej; document.head.append(s); }); },

  /* طابور الرفع المؤجل — يحتفظ بالمستند بتاريخ حفظه الأصلي (updatedAt) دون مسّ */
  enqueue(storeName, obj) {
    return DB.put('outbox', {
      id: `${storeName}__${obj.id || 'app'}`, // مفتاح مركّب: تعديلات المستند نفسه تنهار إلى أحدث نسخة
      store: storeName, docId: obj.id || 'app', data: obj, ts: Date.now(),
    }).catch(() => {});
  },
  /* رفع كل المعلَّق بترتيبه الزمني — set بنفس المعرف idempotent، ولا يُحذف من الطابور إلا بعد تأكيد الإرسال */
  flush() {
    if (!this.ready) return;
    DB.all('outbox').then(q => {
      q.sort((a, b) => a.ts - b.ts).forEach(entry => {
        const req = entry.store === 'settings'
          ? this.fs.collection('settings').doc('app').set(entry.data, { merge: true })
          : this.fs.collection(entry.store).doc(entry.docId).set(entry.data);
        req.then(() => DB.del('outbox', entry.id)).catch(() => {}); // الفشل يُبقي العنصر لإعادة المحاولة
      });
    }).catch(() => {});
  },
  push(storeName, obj) {
    if (storeName === 'meta') return;
    if (!this.ready) { this.enqueue(storeName, obj); return; } // بلا اتصال / SDK لم يُحمَّل → طابور
    const req = storeName === 'settings'
      ? this.fs.collection('settings').doc('app').set(obj, { merge: true })
      : this.fs.collection(storeName).doc(obj.id).set(obj);
    req.catch(() => this.enqueue(storeName, obj)); // رفض الخادم أو خطأ رفع فعلي → طابور
  },
  listen() {
    this.COLLECTIONS.forEach(coll => {
      this.fs.collection(coll).onSnapshot(async snap => {
        let changed = false;
        for (const ch of snap.docChanges()) {
          if (ch.doc.metadata.hasPendingWrites) continue;
          if (ch.type === 'removed') { // حذف نهائي وصل من جهاز آخر: أزله محلياً
            await DB.del(coll, ch.doc.id);
            const arr = state[coll]; const i = arr.findIndex(x => x.id === ch.doc.id);
            if (i >= 0) arr.splice(i, 1);
            changed = true;
            continue;
          }
          const remote = ch.doc.data();
          const local = await DB.get(coll, remote.id);
          if (!local || (remote.updatedAt || 0) > (local.updatedAt || 0)) {
            await DB.put(coll, remote);
            const arr = state[coll]; const i = arr.findIndex(x => x.id === remote.id);
            if (i >= 0) arr[i] = remote; else arr.push(remote);
            changed = true;
          }
        }
        if (changed) refreshActiveTab();
      }, () => {});
    });
        /* مزامنة حية للإعدادات بين الأجهزة (اسم الصيدلية/الشركات/حدود النواقص) */
    this.fs.collection('settings').doc('app').onSnapshot(async snap => {
      if (snap.metadata.hasPendingWrites || !snap.exists) return;
      const remote = snap.data();
      if ((remote.updatedAt || 0) > (state.settings.updatedAt || 0)) {
        state.settings = { id: 'app', ...remote };
        await DB.put('settings', state.settings);
        renderTopbar(); renderSideNav();
      }
    }, () => {});
  },
  async uploadAll() { /* رفع كامل البيانات المحلية (يُستخدم عند أول ربط) */
    if (!this.ready) return;
    for (const coll of this.COLLECTIONS) for (const doc of state[coll]) await this.fs.collection(coll).doc(doc.id).set(doc).catch(() => {});
    await this.fs.collection('settings').doc('app').set(state.settings, { merge: true }).catch(() => {});
  }
};
function setSyncUI(on) {
  const d = $('#sync-dot'), l = $('#sync-label');
  if (d) d.classList.toggle('on', !!on);
  if (l) l.textContent = on ? 'متصل — مزامنة حية' : 'وضع محلي';
}

/* ───────────────────────── 6) التنبيهات والمودالات ───────────────────────── */
function toast(msg, type = 'g') {
  const icons = { g: 'check', r: 'warn', b: 'refresh' };
  const t = h('div', { class: `toast ${type}` }, h('span', { html: icon(icons[type] || 'check') }), msg);
  $('#toast-root').append(t);
  setTimeout(() => { t.classList.add('out'); setTimeout(() => t.remove(), 320); }, 2800);
}
function openModal({ title, icon: ic = 'box', body, actions = [], wide = false, xwide = false, onClose = null, noPad = false }) {
  const root = $('#modal-root');
  const overlay = h('div', { class: 'modal-overlay' });
  const box = h('div', { class: `modal-box${wide ? ' wide' : ''}${xwide ? ' xwide' : ''}` });
  const close = () => { overlay.remove(); if (onClose) onClose(); };
  box.append(
    h('div', { class: 'modal-head' },
      h('h3', {}, h('span', { html: icon(ic) }), title),
      h('button', { class: 'modal-close', html: icon('close'), onclick: close })),
    h('div', { class: 'modal-body', style: noPad ? { padding: 0 } : {} }, body),
  );
  if (actions.length) {
    box.append(h('div', { class: 'modal-foot' }, actions.map(a =>
      h('button', { class: `btn ${a.cls || 'n'}${a.big ? ' big' : ''}`, onclick: () => a.onClick && a.onClick(close) },
        a.icon ? h('span', { html: icon(a.icon) }) : null, a.label))));
  }
  overlay.append(box);
  overlay.addEventListener('mousedown', e => { if (e.target === overlay) close(); });
  root.append(overlay);
  return { close, box };
}
function confirmBox(msg, { danger = false, okLabel = 'تأكيد', icon: ic = 'warn' } = {}) {
  return new Promise(res => {
    let settled = false;
    const settle = v => { if (!settled) { settled = true; res(v); } };
    openModal({
      title: 'تأكيد العملية', icon: ic,
      body: h('p', { style: { fontWeight: 800, fontSize: '15px', lineHeight: 2 } }, msg),
      actions: [
        { label: 'إلغاء', cls: 'n', onClick: c => { settle(false); c(); } },
        { label: okLabel, cls: danger ? 'r' : 'g', onClick: c => { settle(true); c(); } },
      ],
      onClose: () => settle(false),
    });
  });
}
function promptBox(title, { placeholder = '', value = '', type = 'text', okLabel = 'حفظ' } = {}) {
  return new Promise(res => {
    let settled = false;
    const settle = v => { if (!settled) { settled = true; res(v); } };
    const inp = h('input', { type, value, placeholder, style: { width: '100%', border: '1.5px solid var(--line)', borderRadius: '12px', padding: '11px 14px', fontWeight: 800, fontSize: '15px', outline: 'none' } });
    const done = (c) => { const v = inp.value.trim(); settle(v || null); c(); };
    openModal({
      title, icon: 'edit', body: inp,
      actions: [{ label: 'إلغاء', cls: 'n', onClick: c => { settle(null); c(); } }, { label: okLabel, cls: 'g', onClick: done }],
      onClose: () => settle(null),
    });
    inp.focus(); inp.select();
    inp.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); done(() => $('#modal-root').innerHTML = ''); } });
  });
}

/* ───────────────────────── 7) الصور الرمزية الافتراضية ───────────────────────── */
function avatarSVG(gender) {
  if (gender === 'female') {
    return `<svg viewBox="0 0 100 100"><defs><linearGradient id="avf" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#3b82f6"/><stop offset="1" stop-color="#1d4ed8"/></linearGradient></defs><circle cx="50" cy="50" r="50" fill="#eff6ff"/><path d="M50 18c-14 0-22 10-22 24 0 8 2 14 5 18-1 6-3 10-5 13h44c-2-3-4-7-5-13 3-4 5-10 5-18 0-14-8-24-22-24z" fill="url(#avf)"/><circle cx="50" cy="44" r="14" fill="#fde8d8"/><path d="M36 42c0-10 6-16 14-16s14 6 14 16c0 2 0 4-.6 6 1.4-3 .6-8-1.4-10-1 3-4 5-12 5s-11-2-12-5c-2 2-2.8 7-1.4 10-.6-2-.6-4-.6-6z" fill="url(#avf)"/><path d="M28 78c3-9 12-13 22-13s19 4 22 13v4H28z" fill="#fff"/><path d="M28 78c3-9 12-13 22-13s19 4 22 13" fill="none" stroke="#3b82f6" stroke-width="2"/><rect x="44" y="66" width="12" height="4" rx="2" fill="#3b82f6"/></svg>`;
  }
  return `<svg viewBox="0 0 100 100"><defs><linearGradient id="avm" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#22c55e"/><stop offset="1" stop-color="#15803d"/></linearGradient></defs><circle cx="50" cy="50" r="50" fill="#f0fdf4"/><circle cx="50" cy="42" r="15" fill="#fde8d8"/><path d="M35 40c0-9 7-15 15-15s15 6 15 15c0 1.5-.1 3-.4 4.4.8-3.4.2-8.4-2-10.8-1.2 2.8-4.6 4.4-12.6 4.4s-11.4-1.6-12.6-4.4c-2.2 2.4-2.8 7.4-2 10.8-.3-1.4-.4-2.9-.4-4.4z" fill="#334155"/><path d="M26 80c3-11 13-16 24-16s21 5 24 16v6H26z" fill="#fff"/><path d="M26 80c3-11 13-16 24-16s21 5 24 16" fill="none" stroke="url(#avm)" stroke-width="2.5"/><path d="M40 68l6 6 4-8 4 8 6-6" fill="none" stroke="url(#avm)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/><rect x="43" y="64" width="14" height="4" rx="2" fill="url(#avm)"/></svg>`;
}
function accountAvatar(acc, size = 40) {
  const s = avatarNode(acc);
  s.style.width = size + 'px'; s.style.height = size + 'px';
  return s;
}

/* ───────────────────────── 8) شاشة تسجيل الدخول ───────────────────────── */
function renderLogin() {
  const row = $('#accounts-row');
  row.innerHTML = '';
  const accs = state.accounts.filter(a => !a.deleted);
  accs.forEach(acc => {
    const c = h('div', { class: 'acc-circle', onclick: () => openPassword(acc) },
            h('div', { class: 'ring' }, h('div', { class: 'acc-face' }, avatarNode(acc))),
      h('div', { class: 'acc-name' }, acc.name),
      acc.role === 'admin' ? h('div', { class: 'acc-badge' }, 'مدير النظام') : null,
    );
    row.append(c);
  });
  row.append(h('div', { class: 'acc-circle add', onclick: openCreateAccount },
    h('div', { class: 'ring' }, h('div', { class: 'acc-face', html: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" style="width:44px;height:44px"><path d="M12 5v14M5 12h14"/></svg>` })),
    h('div', { class: 'acc-name' }, 'إنشاء حساب')));
  $('#login-pharmacy-name').textContent = state.settings.pharmacyName || 'صيدلية درب الشفاء';
}
function tickLoginClock() {
  const el = $('#login-clock'), d = $('#login-date');
  if (el) el.textContent = `${dayName()} • ${timeStr()}`;
  if (d) d.textContent = fmtDate(Date.now());
}
setInterval(tickLoginClock, 1000);

/* نافذة إنشاء حساب */
function openCreateAccount() {
  let gender = 'male', photo = null;
  const nameInp = h('input', { placeholder: 'مثال: أحمد محمد' });
    const passInp = h('input', { type: 'password', placeholder: 'نص أو أرقام — أي طول مسموح', autocomplete: 'new-password', dir: 'ltr' });
  const fileInp = h('input', { type: 'file', accept: 'image/*' });
  const apInner = h('div', { class: 'ap-inner', html: avatarSVG(gender) });
    fileInp.addEventListener('change', () => readAvatarFile(fileInp, data => {
    photo = data; apInner.innerHTML = ''; apInner.append(avatarNode({ photo, gender }));
  }));
  const gM = h('div', { class: 'gender-opt sel male', onclick: () => pick('male') }, h('span', { html: avatarSVG('male') }), h('b', {}, 'ذكر'));
  const gF = h('div', { class: 'gender-opt', onclick: () => pick('female') }, h('span', { html: avatarSVG('female') }), h('b', {}, 'أنثى'));
  function pick(g) {
    gender = g;
    gM.className = 'gender-opt' + (g === 'male' ? ' sel male' : '');
    gF.className = 'gender-opt' + (g === 'female' ? ' sel' : '');
    if (!photo) apInner.innerHTML = avatarSVG(g);
  }
  const m = openModal({
    title: 'إنشاء حساب جديد', icon: 'user', wide: true,
    body: h('div', { class: 'form-grid' },
      h('div', { class: 'f-field full' }, h('label', {}, 'نوع الجنس'), h('div', { class: 'gender-pick' }, gM, gF)),
      h('div', { class: 'f-field' }, h('label', {}, 'اسم الحساب ', h('span', { class: 'req' }, '*')), nameInp),
      h('div', { class: 'f-field' }, h('label', {}, 'كلمة المرور ', h('span', { class: 'req' }, '*')), passInp),
      h('div', { class: 'f-field full' },
        h('label', {}, 'صورة الحساب (اختياري)'),
        h('div', { class: 'avatar-preview' },
          h('div', { class: 'ap-frame' }, apInner,
            h('label', { class: 'ap-edit', html: icon('camera') }, fileInp))),
        h('div', { class: 'f-hint', style: { textAlign: 'center', color: 'var(--faint)', fontSize: '11.5px', fontWeight: 700 } },
          'إذا لم تختر صورة، سيُمنح الحساب صورة طبية افتراضية حسب الجنس')),
    ),
    actions: [
      { label: 'إلغاء', cls: 'n', onClick: c => c() },
      { label: 'إنشاء الحساب', cls: 'g', icon: 'check', big: true, onClick: async c => {
                const name = nameInp.value.trim(), pass = passInp.value;
        if (!name) return toast('أدخل اسم الحساب', 'r');
        if (!pass) return toast('أدخل كلمة المرور (حتى حرف واحد يكفي)', 'r');
        if (state.accounts.some(a => !a.deleted && a.name === name)) return toast('يوجد حساب بهذا الاسم مسبقاً', 'r');
        const firstAdmin = !state.accounts.some(a => !a.deleted); // أول حساب بالنظام = مدير تلقائياً
        const acc = { id: uid(), name, gender, photo, role: firstAdmin ? 'admin' : 'staff', createdAt: Date.now() };
        await setPassword(acc, pass); // بصمة PBKDF2 + ملح عشوائي — لا نص صريح
        await save('accounts', acc);
        c(); renderLogin();
        toast(`تم إنشاء حساب «${name}» بنجاح`);
      } },
    ],
  });
}

/* نافذة كلمة المرور — حقل نصي كامل (أحرف/أرقام/رموز وبأي طول حتى حرف واحد) + قفل ضد التخمين */
function openPassword(acc) {
  const lockMsg = h('div', { class: 'lock-msg', style: { display: 'none' } },
    h('span', { html: icon('warn') }), 'محاولات فاشلة كثيرة — الحساب مقفل مؤقتاً، تبقى ', h('b', {}, '0'), ' ثانية');
  const passInp = h('input', { type: 'password', class: 'pass-input', placeholder: 'كلمة المرور', autocomplete: 'current-password', dir: 'ltr' });
  const syncLock = () => {
    const w = guardWait(acc.id);
    lockMsg.style.display = w ? 'flex' : 'none';
    if (w) lockMsg.querySelector('b').textContent = w;
  };
  passInp.addEventListener('input', syncLock);
  let busy = false;
  const enterBtn = h('button', { class: 'btn g big', style: { width: '100%', marginTop: '14px' } }, h('span', { html: icon('check') }), 'دخول');
  const tryLogin = async () => {
    if (busy) return;
    if (guardWait(acc.id)) { syncLock(); return; }
    busy = true; enterBtn.disabled = true;
    try {
      if (await verifyPassword(acc, passInp.value)) {
        guardOK(acc.id); m.close(); await login(acc);
        if (acc.mustChangePass) setTimeout(() => { openTab('settings'); toast('كلمة مرورك افتراضية ومعروفة — غيّرها الآن من قسم «حسابي»', 'r'); }, 700);
      } else {
        guardFail(acc.id); syncLock();
        passInp.value = ''; passInp.classList.add('err');
        setTimeout(() => passInp.classList.remove('err'), 450);
        if (!guardWait(acc.id)) toast('كلمة المرور غير صحيحة', 'r');
      }
    } finally { busy = false; enterBtn.disabled = false; if (document.body.contains(passInp)) passInp.focus(); }
  };
  enterBtn.addEventListener('click', tryLogin);
  passInp.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); tryLogin(); } });
  const m = openModal({
    title: 'تسجيل الدخول', icon: 'lock',
    body: h('div', { style: { textAlign: 'center' } },
      h('div', { class: 'avatar-preview' }, h('div', { class: 'ap-frame' }, h('div', { class: 'ap-inner' }, avatarNode(acc)))),
      h('h3', { style: { fontWeight: 900, fontSize: '19px' } }, acc.name),
      h('p', { style: { color: 'var(--muted)', fontWeight: 700, fontSize: '13px' } }, 'أدخل كلمة المرور للمتابعة — أي أحرف أو أرقام وبأي طول'),
      h('div', { class: 'pass-row' }, passInp,
        h('button', { class: 'pass-eye', type: 'button', title: 'إظهار / إخفاء', html: icon('eye'),
          onclick: () => { passInp.type = passInp.type === 'password' ? 'text' : 'password'; passInp.focus(); } })),
      lockMsg, enterBtn),
  });
  syncLock();
  setTimeout(() => passInp.focus(), 60);
}

async function login(acc) {
  state.session = acc.id;
  state.customerId = null;
  $('#login-screen').classList.add('hidden');
  $('#app').classList.remove('hidden');
  renderTopbar(); renderSideNav();
  tabs = [];
  openTab('pos');
  toast(`مرحباً بك، ${acc.name}`);
}
function logout() {
  state.session = null;
  $('#app').classList.add('hidden');
  $('#login-screen').classList.remove('hidden');
  $('#content').innerHTML = ''; $('#tabs').innerHTML = '';
  tabs = [];
  renderLogin(); tickLoginClock();
}

/* ───────────────────────── 9) الهيكل: الشريط العلوي + الجانبي ───────────────────────── */
const NAV = [
  { type: 'pos',         label: 'نقطة البيع',      icon: 'pos' },
  { type: 'returnsale',  label: 'إرجاع بيع',       icon: 'refresh' },
  { type: 'sales',       label: 'تقرير المبيعات',   icon: 'report' },
  { type: 'inventory',   label: 'المخزن',           icon: 'store' },
  { type: 'purchase',    label: 'قائمة شراء',       icon: 'purchase' },
  { type: 'returnpurch', label: 'إرجاع شراء',       icon: 'refresh' },
  { type: 'preport',     label: 'تقرير المشتريات',  icon: 'history' },
  { type: 'suppliers',   label: 'حسابات مجهزين',    icon: 'suppliers' },
  { type: 'statement',   label: 'كشف حساب',         icon: 'receipt' },
  { type: 'settings',    label: 'الإعدادات',        icon: 'settings' },
];
function renderTopbar() {
  const acc = me(); if (!acc) return;
  $('#tb-pharmacy-name').textContent = state.settings.pharmacyName;
  const emp = $('#tb-employee');
  emp.innerHTML = '';
    emp.append(accountAvatar(acc, 28), h('b', {}, acc.name),
    acc.role === 'admin' ? h('span', { class: 'badge b' }, 'مدير') : null);
  renderCustomerSelect();
  const lo = $('#btn-logout');
  lo.innerHTML = icon('logout'); lo.onclick = logout;
  tickTopClock();
}
function renderCustomerSelect() {
  const box = $('#tb-customer');
  box.innerHTML = '';
  const sel = h('select', {},
    h('option', { value: '' }, 'زبون نقدي (عام)'),
    state.customers.map(c => h('option', { value: c.id, selected: state.customerId === c.id }, c.name)));
  sel.addEventListener('change', () => { state.customerId = sel.value || null; });
  const addBtn = h('button', { class: 'icon-btn edit', title: 'إضافة زبون جديد', html: icon('plus'),
    onclick: async () => {
      const name = await promptBox('إضافة زبون جديد', { placeholder: 'اسم الزبون' });
      if (!name) return;
      const c = { id: uid(), name, createdAt: Date.now() };
      await save('customers', c);
      state.customerId = c.id;
      renderCustomerSelect();
      toast(`تمت إضافة الزبون «${name}»`);
    } });
  box.append(h('span', { html: icon('users'), style: { display: 'flex', color: 'var(--blue)' } }), sel, addBtn);
}
function tickTopClock() {
  if (!state.session) return;
  $('#tb-day').textContent = dayName();
  $('#tb-date').textContent = fmtDate(Date.now());
  $('#tb-clock').textContent = timeStr();
}
setInterval(tickTopClock, 1000);
function renderSideNav() {
  const nav = $('#side-nav');
  nav.innerHTML = '';
  const lowCount = state.products.filter(p => !p.deleted && (p.stockBase || 0) <= (state.settings.lowStock ?? 10)).length;
  NAV.forEach(n => {
        const item = h('div', { class: 'nav-item', dataset: { nav: n.type }, onclick: () => {
      if (n.type === 'pos') { const first = tabs.find(t => t.type === 'pos'); if (first) { activateTab(first.id); return; } } // تنقّل لأول نقطة بيع مفتوحة — التبويب الجديد حصرياً من زر +
      openTab(n.type);
    } },
      h('span', { html: icon(n.icon) }), n.label,
      n.type === 'inventory' && lowCount ? h('span', { class: 'nav-count' }, lowCount) : null);
    nav.append(item);
  });
  markActiveNav();
}
function markActiveNav() {
  const act = tabs.find(t => t.id === activeTabId);
  $$('#side-nav .nav-item').forEach(el =>
        el.classList.toggle('active', !!act && el.dataset.nav === act.type && ['pos','returnsale','sales','inventory','purchase','returnpurch','preport','suppliers','statement','settings'].includes(act.type)));
}

/* ───────────────────────── 10) مدير التبويبات (نمط المتصفح) ───────────────────────── */
let tabs = [], activeTabId = null, posCounter = 1;
const LIVE_TABS = ['sales','inventory','preport','suppliers','statement']; // تبويبات تقريرية تُحدَّث تلقائياً عند فتحها
const TAB_META = {
  pos:       { title: () => `نقطة بيع ${'' + ''}`.trim() || 'نقطة بيع', icon: 'pos' },
  sales:     { title: () => 'تقرير المبيعات',  icon: 'report' },
  inventory: { title: () => 'المخزن',          icon: 'store' },
  purchase:  { title: () => 'قائمة شراء',      icon: 'purchase' },
  preport:   { title: () => 'تقرير المشتريات', icon: 'history' },
  suppliers: { title: () => 'حسابات مجهزين',   icon: 'suppliers' },
    settings:  { title: () => 'الإعدادات',       icon: 'settings' },
  returnsale:  { title: () => 'إرجاع بيع',     icon: 'refresh' },
  returnpurch: { title: () => 'إرجاع شراء',    icon: 'refresh' },
  statement:   { title: () => 'كشف حساب',      icon: 'receipt' },
  product:   { title: () => 'إضافة صنف',       icon: 'pill' },
  editsale:  { title: () => 'تعديل قائمة بيع', icon: 'edit' },
  editpurch: { title: () => 'تعديل قائمة شراء',icon: 'edit' },
  details:   { title: () => 'تفاصيل صنف',      icon: 'eye' },
  scanner:   { title: () => 'ماسح الفواتير',   icon: 'camera' },
};
function openTab(type, props = {}) {
  // التبويبات الفريدة: واحد من كل نوع (عدا نقطة البيع والتعديلات والتفاصيل)
    const singleton = ['sales','inventory','preport','suppliers','settings','purchase','scanner','returnsale','returnpurch','statement'];
  if (singleton.includes(type)) {
    const ex = tabs.find(t => t.type === type);
    if (ex) { activateTab(ex.id); return ex; }
  }
  let title = props.title || TAB_META[type].title();
  if (type === 'pos' && !props.title) title = `نقطة بيع ${tabs.filter(t => t.type === 'pos').length + 1}`;
  const tab = { id: uid(), type, title, icon: TAB_META[type].icon, props, state: props.state || {} };
  tab.el = h('div', { class: 'tab-pane', dataset: { tab: tab.id } });
  $('#content').append(tab.el);
  tabs.push(tab);
  renderTabStrip();
  activateTab(tab.id);
  renderTabContent(tab);
  return tab;
}
function closeTab(id) {
  const i = tabs.findIndex(t => t.id === id);
  if (i < 0) return;
  tabs[i].el.remove();
  tabs.splice(i, 1);
  if (!tabs.length) { openTab('pos'); return; }
  if (activeTabId === id) activateTab(tabs[Math.max(0, i - 1)].id);
  renderTabStrip();
}
function activateTab(id) {
  activeTabId = id;
  tabs.forEach(t => t.el.classList.toggle('active', t.id === id));
  renderTabStrip();
  markActiveNav();
  const t = tabs.find(x => x.id === id);
  if (t && LIVE_TABS.includes(t.type)) renderTabContent(t); // بيانات طازجة عند كل فتح للتبويب
}
function renderTabStrip() {
  const box = $('#tabs');
  box.innerHTML = '';
  tabs.forEach(t => {
    box.append(h('div', { class: 'tab' + (t.id === activeTabId ? ' active' : ''), onclick: () => activateTab(t.id) },
      h('span', { html: icon(t.icon) }),
      h('span', { class: 'tab-title' }, t.title),
      h('span', { class: 'tab-close', html: icon('close'), onclick: e => { e.stopPropagation(); closeTab(t.id); } })));
  });
  markActiveNav();
}
function renderTabContent(tab) {
  const R = {
    pos: renderPOS, sales: renderSalesReport, inventory: renderInventory,
    purchase: renderPurchase, preport: renderPurchaseReport, suppliers: renderSuppliers,
    settings: renderSettings, product: renderProductForm, editsale: renderEditSale,
        editpurch: renderEditPurchase, details: renderProductDetails, scanner: renderScannerTab,
    returnsale: renderReturnSale, returnpurch: renderReturnPurchase, statement: renderStatement,
  };
  tab.el.innerHTML = '';
  (R[tab.type] || renderPOS)(tab);
}
function refreshActiveTab() {
  const t = tabs.find(x => x.id === activeTabId);
    if (t && !['pos','editsale','editpurch','product','purchase','returnsale','returnpurch'].includes(t.type)) renderTabContent(t);
  renderSideNav();
}

/* ───────────────────────── 11) مساعدات المنتجات والتعبئة ───────────────────────── */
// units: [{name, perNext}] من الأكبر للأصغر — الأخيرة هي الوحدة الصغرى (perNext=1)
function unitFactor(p, idx) { let f = 1; for (let i = idx; i < p.units.length; i++) f *= (p.units[i].perNext || 1); return f; }
function baseFactor(p) { return unitFactor(p, 0); }
function costPerUnit(p, idx) { return (p.purchasePriceTop / baseFactor(p)) * unitFactor(p, idx); }
function salePerUnit(p, idx) { return p.salePriceBase * unitFactor(p, idx); }
function stockInUnit(p, idx) { return Math.floor((p.stockBase || 0) / unitFactor(p, idx) * 100) / 100; }
function smallUnitName(p) { return p.units[p.units.length - 1].name; }
function bigUnitName(p) { return p.units[0].name; }
function searchProducts(q) {
  q = q.trim().toLowerCase();
  if (!q) return [];
  const exactBarcode = state.products.find(p => !p.deleted && (p.barcodes || []).some(b => b.toLowerCase() === q));
  if (exactBarcode) return [exactBarcode];
  return state.products.filter(p => !p.deleted && (
    p.brandName.toLowerCase().includes(q) ||
    (p.scientificName || '').toLowerCase().includes(q) ||
    (p.dose || '').toLowerCase().includes(q) ||
    (p.company || '').toLowerCase().includes(q) ||
    (p.barcodes || []).some(b => b.toLowerCase().includes(q))
  )).slice(0, 12);
}

/* ───────────────────────── 12) نقطة البيع ───────────────────────── */
function renderPOS(tab) {
  const st = tab.state;
  st.cart = st.cart || [];           // [{productId,name,unitIdx,qty,cost,sale}]
  st.discount = st.discount || 0;
  st.sideTab = st.sideTab || 'featured';

  const wrap = h('div', { class: 'pos-layout' });
  const center = h('div', { class: 'pos-center' });

  /* محرك البحث */
  const sInput = h('input', { placeholder: 'ابحث بالاسم أو أدخل الباركود…', autocomplete: 'off' });
  const sugBox = h('div', { class: 'suggestions' });
  st.searchInput = sInput;
  let selIdx = -1, sugItems = [];
  function renderSugs() {
    const q = sInput.value;
    sugItems = searchProducts(q); selIdx = -1;
    sugBox.innerHTML = '';
    if (!q.trim()) { sugBox.classList.remove('show'); return; }
    if (!sugItems.length) {
      sugBox.append(h('div', { class: 'sug-empty' }, `لا نتائج لـ «${q}» — أضف الصنف من قائمة الشراء`));
    } else {
      sugItems.forEach((p, i) => {
        sugBox.append(h('div', { class: 'sug-item', onclick: () => { pickProduct(p); } },
          h('span', { class: 'sug-ic', html: icon('pill') }),
          h('div', { class: 'sug-name' }, p.brandName, coTag(p),
            h('small', {}, `${p.scientificName || ''}${p.scientificName ? ' • ' : ''}${p.form || ''} ${p.dose || ''}`)),
          h('span', { class: 'sug-stock' + ((p.stockBase || 0) <= (state.settings.lowStock ?? 10) ? ' low' : '') },
            `المخزون: ${fmt(p.stockBase || 0)} ${smallUnitName(p)}`),
          h('span', { class: 'sug-price' }, `${fmt(salePerUnit(p, p.units.length - 1))} ${cur()}`)));
      });
    }
    sugBox.classList.add('show');
  }
  function pickProduct(p) {
    addToCart(tab, p);
    sInput.value = ''; sugBox.classList.remove('show'); sInput.focus();
  }
  sInput.addEventListener('input', renderSugs);
  sInput.addEventListener('keydown', e => {
    if (e.key === 'Enter') {
      const q = sInput.value.trim();
      if (selIdx >= 0 && sugItems[selIdx]) pickProduct(sugItems[selIdx]);
      else if (sugItems.length === 1 || (q && sugItems.length)) pickProduct(sugItems[0]);
      else if (q) toast('لا يوجد صنف مطابق', 'r');
    } else if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      if (!sugItems.length) return;
      selIdx = e.key === 'ArrowDown' ? Math.min(selIdx + 1, sugItems.length - 1) : Math.max(selIdx - 1, 0);
      $$('.sug-item', sugBox).forEach((el, i) => el.classList.toggle('sel', i === selIdx));
    } else if (e.key === 'Escape') { sugBox.classList.remove('show'); }
  });
  document.addEventListener('mousedown', e => { if (!sugBox.contains(e.target) && e.target !== sInput) sugBox.classList.remove('show'); });
  center.append(h('div', { class: 'search-engine' },
    h('div', { class: 'search-box' }, h('span', { html: icon('search') }), sInput,
      h('span', { class: 'search-hint' }, 'أي كتابة تذهب هنا تلقائياً')), sugBox));

  /* جدول السلة */
  const cartWrap = h('div', { class: 'cart-wrap' });
  st.renderCart = () => {
    cartWrap.innerHTML = '';
    if (!st.cart.length) {
      cartWrap.append(h('div', { class: 'cart-empty' },
        h('span', { html: icon('pos').replace('width="20" height="20"', 'width="74" height="74"') }),
        h('p', {}, 'السلة فارغة — ابحث عن صنف أو امسح باركود للبدء')));
      return;
    }
    const tbody = h('tbody');
    st.cart.forEach((it, i) => {
      const p = findProd(it.productId);
      tbody.append(h('tr', {},
        h('td', { class: 'td-seq' }, i + 1),
        h('td', { class: 'td-name' }, it.name, coTag(p), h('small', {}, p ? `${p.form || ''} ${p.dose || ''}` : '')),
        h('td', {}, (() => {
          const sel = h('select', { class: 'unit-select' },
            (p ? p.units : [{ name: it.unitName }]).map((u, ui) =>
              h('option', { value: ui, selected: ui === it.unitIdx }, u.name)));
          sel.addEventListener('change', () => {
            it.unitIdx = +sel.value;
            if (p) { it.sale = salePerUnit(p, it.unitIdx); it.cost = costPerUnit(p, it.unitIdx); }
            st.renderCart(); st.renderTotals();
          });
          return sel;
        })()),
        h('td', {}, (() => {
          const q = h('input', { type: 'number', value: it.qty, min: 0.5, step: 'any' });
          q.addEventListener('change', () => { it.qty = Math.max(0.5, num(q.value) || 1); st.renderCart(); st.renderTotals(); });
          return h('div', { class: 'qty-ctl' },
            h('button', { onclick: () => { it.qty++; st.renderCart(); st.renderTotals(); } }, '+'), q,
            h('button', { onclick: () => { if (it.qty > 1) { it.qty--; st.renderCart(); st.renderTotals(); } } }, '−'));
        })()),
        h('td', { class: 'td-num td-cost' }, fmt(it.cost)),
        h('td', { class: 'td-num td-sale' }, fmt(it.sale)),
        h('td', { class: 'td-num td-total' }, fmt(it.sale * it.qty)),
        h('td', {}, h('div', { class: 'row-act' },
          h('button', { class: 'icon-btn view', title: 'تفاصيل المنتج', html: icon('eye'), onclick: () => openTab('details', { productId: it.productId }) }),
          h('button', { class: 'icon-btn del', title: 'حذف من السلة', html: icon('trash'), onclick: () => { st.cart.splice(i, 1); st.renderCart(); st.renderTotals(); } }))),
      ));
    });
    cartWrap.append(h('div', { class: 'tbl-scroll' },
      h('table', { class: 'tbl' },
        h('thead', {}, h('tr', {},
          h('th', {}, 'ت'), h('th', {}, 'اسم المنتج'), h('th', {}, 'الوحدة'), h('th', {}, 'العدد'),
          h('th', {}, 'سعر التكلفة'), h('th', {}, 'سعر البيع'), h('th', {}, 'المجموع'), h('th', {}, 'إجراء'))),
        tbody)));
  };

  /* الإجماليات والأزرار */
  const subEl = h('div', { class: 'tval' }, '0');
  const grandEl = h('div', { class: 'tval' }, h('span', {}, '0'), ' ', h('small', {}, cur()));
  const discInp = h('input', { type: 'number', min: 0, placeholder: '0', value: st.discount || '' });
  const peekTip = h('div', { class: 'peek-tip' });
  discInp.addEventListener('input', () => { st.discount = num(discInp.value); st.renderTotals(); });
  discInp.addEventListener('blur', () => { if (tab.id === activeTabId) sInput.focus(); });
  st.renderTotals = () => {
    const sub = st.cart.reduce((s, it) => s + it.sale * it.qty, 0);
    const profit = st.cart.reduce((s, it) => s + (it.sale - it.cost) * it.qty, 0) - st.discount;
    subEl.textContent = fmt(sub);
    grandEl.firstChild.textContent = fmt(Math.max(0, sub - st.discount));
    peekTip.innerHTML = `<small>الربح الصافي من هذه القائمة</small>${fmt(profit)} ${cur()}`;
  };

  const footer = h('div', { class: 'pos-footer' },
    h('div', { class: 'totals-row' },
      h('div', { class: 'total-card' }, h('label', {}, 'مجموع القائمة'), subEl),
      h('div', { class: 'total-card' }, h('label', {}, 'الخصم'),
        h('div', { class: 'discount-wrap' }, discInp,
          h('div', { class: 'profit-peek', html: icon('dollar') }, peekTip))),
      h('div', { class: 'total-card grand' }, h('label', {}, 'المبلغ المطلوب'), grandEl)),
    h('div', { class: 'pay-row' },
      h('button', { class: 'pay-btn cash', onclick: () => checkout(tab, 'cash') },
        h('span', { html: icon('cash') }), 'بيع كاش ', h('kbd', {}, 'Ctrl+S')),
      h('button', { class: 'pay-btn electronic', onclick: () => checkout(tab, 'electronic') },
        h('span', { html: icon('card') }), 'بيع إلكتروني'),
      h('button', { class: 'pay-btn credit', onclick: () => checkout(tab, 'credit') },
        h('span', { html: icon('clock') }), 'بيع آجل')));

  center.append(cartWrap);
  const layoutInner = h('div', { style: { flex: 1, display: 'flex', minHeight: 0 } }, center, renderPOSSide(tab));
  wrap.append(layoutInner, footer);
  tab.el.append(wrap);
  st.renderCart(); st.renderTotals();
  setTimeout(() => sInput.focus(), 60);
}

function addToCart(tab, p) {
  const st = tab.state;
  const ex = st.cart.find(it => it.productId === p.id && it.unitIdx === p.units.length - 1);
  if (ex) { ex.qty++; }
  else st.cart.push({
    productId: p.id, name: p.brandName, unitIdx: p.units.length - 1,
    qty: 1, cost: costPerUnit(p, p.units.length - 1), sale: salePerUnit(p, p.units.length - 1),
  });
  st.renderCart(); st.renderTotals();
}

/* تنفيذ البيع */
async function checkout(tab, pay) {
  const st = tab.state;
  if (!st.cart.length) return toast('السلة فارغة', 'r');
    if (pay === 'credit' && !state.customerId) return toast('البيع الآجل يتطلب اختيار زبون من الشريط العلوي', 'r');
  st.processing = true; // قفل مؤقت لمنع الضغط المزدوج على أزرار البيع
  const acc = me();
  const items = st.cart.map(it => {
    const p = findProd(it.productId);
    return { ...it, unitName: p ? p.units[it.unitIdx].name : it.unitName || '', qtyBase: p ? it.qty * unitFactor(p, it.unitIdx) : it.qty, total: it.sale * it.qty };
  });
  const subtotal = items.reduce((s, it) => s + it.total, 0);
  const cost = items.reduce((s, it) => s + it.cost * it.qty, 0);
  const net = Math.max(0, subtotal - st.discount);
  const ts = Date.now();
  const sale = {
    id: uid(), type: 'sale', version: 1, versions: [],
    items, subtotal, discount: st.discount, net, cost, profit: net - cost,
    pay, customerId: state.customerId, customerName: state.customerId ? (findCust(state.customerId) || {}).name : 'زبون نقدي',
    employeeId: acc.id, employeeName: acc.name,
    ts, date: dateStr(ts), time: timeStr(ts), deviceId: DEVICE_ID,
  };
  await save('sales', sale);
  for (const it of items) {  // خصم المخزون فوراً
    const p = findProd(it.productId);
    if (p) { p.stockBase = (p.stockBase || 0) - it.qtyBase; await save('products', p); }
  }
    st.cart = []; st.discount = 0; st.processing = false;
  renderTabContent(tab); // إعادة بناء كاملة للتبويب — تمنع تكرار الواجهة نهائياً
  renderSideNav();
  toast(`تمت عملية البيع بنجاح — ${fmt(net)} ${cur()}`);
}

/* اللوح الجانبي لنقطة البيع */
function renderPOSSide(tab) {
  const st = tab.state;
  const side = h('div', { class: 'pos-side' });
  const body = h('div', { class: 'side-body' });
  const tabsBar = h('div', { class: 'side-tabs' },
    ...[['featured','المميز'],['invoices','الفواتير السابقة'],['shortage','النواقص'],['shift','تقرير الشفت']].map(([k, l]) =>
      h('div', { class: 'side-tab' + (st.sideTab === k ? ' active' : ''), onclick: () => { st.sideTab = k; draw(); } }, l)));
  function draw() {
    $$('.side-tab', tabsBar).forEach((el, i) => el.classList.toggle('active', ['featured','invoices','shortage','shift'][i] === st.sideTab));
    body.innerHTML = '';
    if (st.sideTab === 'featured') drawFeatured(tab, body);
    else if (st.sideTab === 'invoices') drawInvoices(body);
    else if (st.sideTab === 'shortage') drawShortage(body);
    else drawShift(body);
  }
  side.append(tabsBar, body);
  draw();
  return side;
}
function drawFeatured(tab, body) {
  body.append(h('div', { class: 'side-actions' },
    h('button', { class: 'mini-btn green', onclick: () => pickFeaturedModal() }, h('span', { html: icon('plus') }), 'إضافة'),
    h('button', { class: 'mini-btn red', onclick: () => removeFeaturedModal() }, h('span', { html: icon('trash') }), 'حذف')));
  const feats = state.products.filter(p => !p.deleted && p.featured);
  if (!feats.length) { body.append(h('div', { class: 'empty-note' }, 'لا أصناف مميزة بعد', h('br'), 'أضفها بزر الإضافة أعلاه')); return; }
  const grid = h('div', { class: 'feat-grid' });
  feats.forEach(p => grid.append(h('div', { class: 'feat-cell', onclick: () => { addToCart(tab, p); } },
    h('span', { html: icon('pill') }), p.brandName,
    h('span', { class: 'feat-price' }, `${fmt(salePerUnit(p, p.units.length - 1))} ${cur()}`))));
  body.append(grid);
}
function pickFeaturedModal() {
  const inp = h('input', { placeholder: 'ابحث عن الصنف…', style: { width: '100%', border: '1.5px solid var(--line)', borderRadius: '12px', padding: '11px 14px', fontWeight: 800, outline: 'none' } });
  const list = h('div', { style: { marginTop: '12px', maxHeight: '300px', overflowY: 'auto' } });
  const draw = () => {
    list.innerHTML = '';
    const res = searchProducts(inp.value).filter(p => !p.featured);
    if (!res.length) { list.append(h('div', { class: 'empty-note' }, inp.value ? 'لا نتائج' : 'اكتب للبحث')); return; }
    res.forEach(p => list.append(h('div', { class: 'inv-mini', onclick: async () => { p.featured = true; await save('products', p); m.close(); refreshActiveTab(); toast(`«${p.brandName}» أصبح مميزاً`); } },
      h('div', { class: 'im-top' }, h('span', {}, p.brandName), h('b', {}, `${fmt(salePerUnit(p, p.units.length - 1))}`)))));
  };
  inp.addEventListener('input', draw); draw();
  const m = openModal({ title: 'إضافة صنف للمميز', icon: 'star', body: h('div', {}, inp, list) });
  inp.focus();
}
function removeFeaturedModal() {
  const feats = state.products.filter(p => !p.deleted && p.featured);
  const list = h('div', { style: { maxHeight: '320px', overflowY: 'auto' } });
  if (!feats.length) list.append(h('div', { class: 'empty-note' }, 'لا أصناف مميزة'));
  feats.forEach(p => list.append(h('div', { class: 'inv-mini', onclick: async () => { p.featured = false; await save('products', p); m.close(); refreshActiveTab(); toast(`أُزيل «${p.brandName}» من المميز`, 'b'); } },
    h('div', { class: 'im-top' }, h('span', {}, p.brandName), h('span', { class: 'badge r' }, 'إزالة من المميز')))));
  const m = openModal({ title: 'حذف من المميز', icon: 'trash', body: list });
}
function drawInvoices(body) {
  const today = dateStr();
  const recent = state.sales.filter(s => s.type === 'sale').sort((a, b) => b.ts - a.ts).slice(0, 30);
  if (!recent.length) { body.append(h('div', { class: 'empty-note' }, 'لا فواتير بعد')); return; }
  recent.forEach(s => body.append(h('div', { class: 'inv-mini', onclick: () => viewSaleModal(s) },
    h('div', { class: 'im-top' }, h('span', {}, `${s.employeeName} • ${s.customerName || 'زبون نقدي'}`), h('b', {}, `${fmt(s.net)} ${cur()}`)),
    h('div', { class: 'im-sub' }, h('span', {}, `${fmtDate(s.ts)} ${fmtTime(s.ts)}`),
      h('span', { class: 'badge ' + (s.pay === 'cash' ? 'g' : s.pay === 'electronic' ? 'b' : 'r') },
        s.pay === 'cash' ? 'كاش' : s.pay === 'electronic' ? 'إلكتروني' : 'آجل')))));
}
function viewSaleModal(s) {
  const rows = s.items.map((it, i) => h('tr', {},
    h('td', { class: 'td-seq' }, i + 1), h('td', { class: 'td-name' }, it.name),
    h('td', {}, it.unitName), h('td', { class: 'td-num' }, fmt(it.qty)),
    h('td', { class: 'td-num' }, fmt(it.sale)), h('td', { class: 'td-num td-total' }, fmt(it.total))));
  openModal({
    title: `فاتورة — ${fmtDate(s.ts)} ${fmtTime(s.ts)}`, icon: 'receipt', wide: true,
    body: h('div', {},
      h('table', { class: 'tbl' }, h('thead', {}, h('tr', {},
        h('th', {}, 'ت'), h('th', {}, 'المنتج'), h('th', {}, 'الوحدة'), h('th', {}, 'العدد'), h('th', {}, 'السعر'), h('th', {}, 'المجموع'))),
        h('tbody', {}, rows)),
      h('div', { style: { display: 'flex', gap: '10px', marginTop: '14px' } },
        h('div', { class: 'sum-card n' }, h('label', {}, 'المجموع'), h('b', {}, fmt(s.subtotal))),
        h('div', { class: 'sum-card r' }, h('label', {}, 'الخصم'), h('b', {}, fmt(s.discount))),
        h('div', { class: 'sum-card big' }, h('label', {}, 'الصافي'), h('b', {}, `${fmt(s.net)} ${cur()}`)))),
  });
}
function drawShortage(body) {
  const low = state.products.filter(p => !p.deleted && (p.stockBase || 0) <= (state.settings.lowStock ?? 10))
    .sort((a, b) => (a.stockBase || 0) - (b.stockBase || 0));
  if (!low.length) { body.append(h('div', { class: 'empty-note' }, 'ممتاز! لا نواقص حالياً')); return; }
  low.forEach(p => body.append(h('div', { class: 'inv-mini', onclick: () => openTab('details', { productId: p.id }) },
    h('div', { class: 'im-top' }, h('span', {}, p.brandName),
      h('span', { class: 'badge ' + ((p.stockBase || 0) <= 0 ? 'r' : 'amber') }, `${fmt(p.stockBase || 0)} ${smallUnitName(p)}`)),
    h('div', { class: 'im-sub' }, h('span', {}, p.scientificName || p.form || ''), h('span', {}, (p.stockBase || 0) <= 0 ? 'نافد' : 'شبه نافد')))));
}
function drawShift(body) {
  const acc = me();
  const today = dateStr();
  const mine = state.sales.filter(s => s.employeeId === acc.id && s.date === today);
  const sales = mine.filter(s => s.type === 'sale'), returns = mine.filter(s => s.type === 'return');
  const cash = sales.filter(s => s.pay === 'cash').reduce((x, s) => x + s.net, 0);
  const elec = sales.filter(s => s.pay === 'electronic').reduce((x, s) => x + s.net, 0);
  const cred = sales.filter(s => s.pay === 'credit').reduce((x, s) => x + s.net, 0);
  const ret = returns.reduce((x, s) => x + s.net, 0);
  const profit = mine.reduce((x, s) => x + s.profit, 0);
  body.append(h('div', { class: 'shift-cards' },
    h('div', { class: 'shift-card n' }, h('label', {}, `عدد قوائم اليوم (${acc.name})`), h('b', {}, sales.length)),
    h('div', { class: 'shift-card g' }, h('label', {}, 'مبيعات كاش'), h('b', {}, `${fmt(cash)} ${cur()}`)),
    h('div', { class: 'shift-card b' }, h('label', {}, 'مبيعات إلكترونية'), h('b', {}, `${fmt(elec)} ${cur()}`)),
    h('div', { class: 'shift-card r' }, h('label', {}, 'مبيعات آجلة'), h('b', {}, `${fmt(cred)} ${cur()}`)),
    h('div', { class: 'shift-card r' }, h('label', {}, 'المرتجعات'), h('b', {}, `${fmt(ret)} ${cur()}`)),
    h('div', { class: 'shift-card g' }, h('label', {}, 'صافي الدخل (كاش + إلكتروني)'), h('b', {}, `${fmt(cash + elec - ret)} ${cur()}`)),
    h('div', { class: 'shift-card b' }, h('label', {}, 'ربح الشفت'), h('b', {}, `${fmt(profit)} ${cur()}`)),
  ));
}

/* ───────────────────────── 13) لوحة المفاتيح الذكية ─────────────────────────
   أي إدخال نصي/رقمي يذهب تلقائياً لمحرك البحث ما لم يكن المستخدم
   داخل حقل إدخال محدد — يعمل مع قارئ الباركود تلقائياً. */
document.addEventListener('keydown', e => {
  if (e.ctrlKey && (e.key === 's' || e.key === 'S')) {
    e.preventDefault();
    const t = tabs.find(x => x.id === activeTabId);
    if (t && t.type === 'pos') checkout(t, 'cash');
    return;
  }
  if (e.ctrlKey || e.altKey || e.metaKey) return;
  if ($('#modal-root').children.length) return; // مودال مفتوح
  const t = tabs.find(x => x.id === activeTabId);
    if (!t || !['pos','returnsale'].includes(t.type) || !t.state.searchInput) return;
  const ae = document.activeElement;
  if (ae && (ae.tagName === 'INPUT' || ae.tagName === 'TEXTAREA' || ae.tagName === 'SELECT' || ae.isContentEditable)) return;
  if (e.key.length === 1) {
    t.state.searchInput.focus();
    t.state.searchInput.value += e.key;
    t.state.searchInput.dispatchEvent(new Event('input'));
    e.preventDefault();
  } else if (e.key === 'Enter' && t.state.searchInput.value.trim()) {
    t.state.searchInput.focus();
    t.state.searchInput.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    e.preventDefault();
  }
});

/* ───────────────────────── 14) صفحة إضافة / تعديل صنف ───────────────────────── */
function genBarcode() {
  state.settings.generatedBarcode = (state.settings.generatedBarcode || 0) + 1;
  const code = String(state.settings.generatedBarcode).padStart(6, '0');
  DB.put('settings', state.settings);
  return code;
}
const FORMS = ['Tab','Cap','Amp','Vial','Gum','Syrup','Susp','Supp'];
const DOSE_UNITS = ['mg','g','ml','mcg','IU','%'];
function renderProductForm(tab) {
  const P = tab.props;
  const existing = P.productId ? findProd(P.productId) : null;
    const f = tab.state.form = existing ? JSON.parse(JSON.stringify(existing)) : {
    brandName: '', scientificName: '', barcodes: P.barcode ? [P.barcode] : [],
    form: 'Tab', dose: '', expiry: '', featured: false, company: '', country: '',
        units: [{ name: 'قطعة', perNext: 1 }],
    purchasePriceTop: 0, salePriceBase: 0, stockBase: 0, supplierId: P.supplierId || null,
  };
    if (!f.units || !f.units.length) f.units = [{ name: 'قطعة', perNext: 1 }];
  f.units[f.units.length - 1].perNext = 1;

  const page = h('div', { class: 'page', style: { overflowY: 'auto' } });
  page.append(h('div', { class: 'page-head' },
    h('div', { class: 'page-title' }, h('span', { html: icon('pill') }), existing ? `تعديل صنف: ${existing.brandName}` : 'إضافة صنف جديد'),
    h('div', { class: 'spacer' }),
    h('button', { class: 'btn b', onclick: () => openTab('scanner', { returnTab: tab.id }) }, h('span', { html: icon('camera') }), 'مسح فاتورة بالذكاء الاصطناعي')));

  const grid = h('div', { class: 'form-grid' });
  const nameInp = h('input', { value: f.brandName, placeholder: 'اسم العلاج التجاري' });
  const sciInp = h('input', { value: f.scientificName || '', placeholder: 'اختياري' });
    /* الشركة المصنعة + البلد — قائمة ذكية: اختر منها، أو اكتب حرفاً للترشيح، أو اكتب اسماً جديداً فيُحفظ */
  if (!Array.isArray(state.settings.companies) || !state.settings.companies.length) state.settings.companies = DEFAULT_COMPANIES.map(c => ({ ...c }));
  const companies = state.settings.companies;
  const compInp = h('input', { value: f.company || '', placeholder: 'اختر من القائمة أو اكتب اسم شركة…', autocomplete: 'off' });
  const compSug = h('div', { class: 'suggestions' });
  const ctryListId = 'ctry-' + tab.id;
  const countryInp = h('input', { value: f.country || '', placeholder: 'تُملأ تلقائياً — ويمكن تعديلها أو كتابتها', list: ctryListId });
  const countryList = h('datalist', { id: ctryListId });
  function drawCountryList() {
    countryList.innerHTML = '';
    [...new Set(companies.map(c => c.country).filter(Boolean))].forEach(ct => countryList.append(h('option', { value: ct })));
  }
  function drawCompSug() {
    const q = compInp.value.trim().toLowerCase();
    compSug.innerHTML = '';
    const res = (q ? companies.filter(c => c.name.toLowerCase().includes(q)) : companies).slice(0, 30);
    res.forEach(c => compSug.append(h('div', { class: 'sug-item', onclick: () => {
      compInp.value = c.name; f.company = c.name;
      if (c.country) { countryInp.value = c.country; f.country = c.country; } // البلد يُملأ تلقائياً
      compSug.classList.remove('show');
    } },
      h('span', { class: 'sug-ic', html: icon('store') }),
      h('div', { class: 'sug-name' }, c.name, h('small', {}, c.country || '')))));
    if (q && !res.length) compSug.append(h('div', { class: 'sug-empty' }, `«${compInp.value.trim()}» غير مسجلة — ستُحفظ كشركة جديدة عند حفظ الصنف`));
    if (res.length || q) compSug.classList.add('show');
  }
  compInp.addEventListener('input', () => { f.company = compInp.value.trim(); drawCompSug(); });
  compInp.addEventListener('focus', drawCompSug);
  compInp.addEventListener('blur', () => setTimeout(() => compSug.classList.remove('show'), 160));
  countryInp.addEventListener('input', () => f.country = countryInp.value.trim());
  drawCountryList();
  const formSel = h('select', {}, FORMS.map(x => h('option', { value: x, selected: f.form === x }, x)), h('option', { value: '__add' }, '＋ إضافة شكل جديد…'));
  formSel.addEventListener('change', async () => {
    if (formSel.value === '__add') {
      const v = await promptBox('إضافة شكل علاجي جديد', { placeholder: 'مثال: Drops' });
      if (v) { FORMS.push(v); formSel.insertBefore(h('option', { value: v }, v), formSel.lastChild); formSel.value = v; }
      else formSel.value = f.form;
    } else f.form = formSel.value;
  });
  const doseInp = h('input', { value: f.dose || '', placeholder: 'مثال: 500', style: { flex: 1 } });
  const doseUnit = h('select', {}, DOSE_UNITS.map(u => h('option', {}, u)));
  const expiryInp = h('input', { type: 'month', value: f.expiry || '' });
  const stockInp = h('input', { type: 'number', min: 0, placeholder: '0' });
  const stockUnit = h('select', {});

  /* الباركودات */
  const bcInp = h('input', { placeholder: 'أدخل باركود ثم Enter', style: { direction: 'ltr' } });
  const bcList = h('div', { class: 'barcode-list' });
  const drawBarcodes = () => {
    bcList.innerHTML = '';
    f.barcodes.forEach((b, i) => bcList.append(h('span', { class: 'barcode-chip' }, b,
      h('button', { html: icon('close'), onclick: () => { f.barcodes.splice(i, 1); drawBarcodes(); } }))));
  };
  const addBarcode = v => {
    v = v.trim();
    if (!v) return;
    if (state.products.some(p => !p.deleted && p.id !== f.id && (p.barcodes || []).includes(v))) return toast('هذا الباركود مستخدم لصنف آخر', 'r');
    if (!f.barcodes.includes(v)) { f.barcodes.push(v); drawBarcodes(); }
    bcInp.value = '';
  };
  bcInp.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); addBarcode(bcInp.value); } });

  /* بناء التعبئة */
    /* بناء التعبئة — أسماء الوحدات من قائمة اختيار (نفس فكرة الشكل العلاجي) */
  const packBox = h('div', { class: 'pack-builder' });
  function unitSelect(u) {
    const names = state.settings.unitNames || [];
    const sel = h('select', { class: 'pname' },
      names.map(n => h('option', { value: n, selected: u.name === n }, n)),
      !names.includes(u.name) ? h('option', { value: u.name, selected: true }, u.name) : null,
      h('option', { value: '__add' }, '＋ إضافة وحدة جديدة…'));
    sel.addEventListener('change', async () => {
      if (sel.value === '__add') {
        const v = await promptBox('إضافة وحدة تعبئة جديدة', { placeholder: 'مثال: علبة' });
        if (v && !names.includes(v)) { state.settings.unitNames.push(v); await DB.put('settings', state.settings); u.name = v; }
      } else u.name = sel.value;
      drawPack(); drawStockUnit(); drawPricePreview();
    });
    return sel;
  }
  function drawPack() {
    packBox.innerHTML = '';
    f.units.forEach((u, i) => {
      const nameI = unitSelect(u);
      const isLast = i === f.units.length - 1;
      const qtyI = h('input', { class: 'pqty', type: 'number', min: 1, value: u.perNext, disabled: isLast, title: 'عدد الوحدات الأصغر داخل هذه الوحدة' });
      qtyI.addEventListener('change', () => { u.perNext = Math.max(1, Math.round(num(qtyI.value)) || 1); drawPricePreview(); });
      packBox.append(h('div', { class: 'pack-row' },
        h('span', { class: 'pnum' }, i + 1), nameI,
        isLast ? h('span', { class: 'parrow' }, 'الوحدة الصغرى (أساس البيع والجرد)')
          : h('span', { class: 'parrow' }, 'تحتوي على'), !isLast ? qtyI : null,
        !isLast ? h('span', { class: 'parrow' }, `من «${f.units[i + 1].name}»`) : null,
        f.units.length > 1 ? h('button', { class: 'pdel', html: icon('trash'), onclick: () => { f.units.splice(i, 1); drawPack(); drawStockUnit(); drawPricePreview(); } }) : null));
    });
        packBox.append(h('button', { class: 'pack-add', onclick: () => {
      if (f.units.length >= 4) return toast('الحد الأقصى 4 مستويات تعبئة', 'r');
      if (f.units.length === 1 && f.units[0].name === 'قطعة') f.units[0].name = 'باكيت'; // قطعة ← باكيت تلقائياً عند أول تقسيم
      f.units[f.units.length - 1].perNext = 10;
      f.units.push({ name: 'شريط', perNext: 1 });
      drawPack(); drawStockUnit(); drawPricePreview();
    } }, h('span', { html: icon('plus') }), 'إضافة وحدة أصغر'));
  }

  /* الأسعار */
    /* الأسعار — أربع خلايا: شراء/بيع للكبرى والصغرى، والمسميات تتبع الوحدات المختارة تلقائياً */
  const buyInp = h('input', { type: 'number', min: 0, value: f.purchasePriceTop || '', placeholder: '0' });
  const pctInp = h('input', { type: 'number', min: 0, value: existing ? '' : (state.settings.profitPct ?? 30), style: { width: '90px' } });
  const sellInp = h('input', { type: 'number', min: 0, value: f.salePriceBase || '', placeholder: '0' });
  const buyTopLbl  = h('label', {}, 'سعر شراء الوحدة الكبرى');
  const sellTopLbl = h('label', {}, 'سعر بيع الوحدة الكبرى');
  const buyBaseLbl = h('label', {}, 'سعر شراء الوحدة الصغرى');
  const sellBaseLbl= h('label', {}, 'سعر بيع الوحدة الصغرى');
  const sellTopView = h('b', { class: 'pq-val' }, '0');
  const buyBaseView = h('b', { class: 'pq-val' }, '0');
  const prevBox = h('div', { class: 'price-preview' });
  function unitF(idx) { let x = 1; for (let i = idx; i < f.units.length; i++) x *= (f.units[i].perNext || 1); return x; }
  function syncFromPct() {
    const buyBase = num(buyInp.value) / (unitF(0) || 1);
    sellInp.value = buyBase ? Math.round(buyBase * (1 + num(pctInp.value) / 100)) : '';
    drawPricePreview();
  }
  function syncFromSell() {
    const buyBase = num(buyInp.value) / (unitF(0) || 1);
    pctInp.value = buyBase && num(sellInp.value) ? Math.round((num(sellInp.value) / buyBase - 1) * 1000) / 10 : pctInp.value;
    drawPricePreview();
  }
    function drawPricePreview() {
    const bf = unitF(0) || 1;
    const buyBase = num(buyInp.value) / bf, sellBase = num(sellInp.value);
    const big = f.units[0].name, small = f.units[f.units.length - 1].name;
    buyTopLbl.textContent  = `سعر شراء الـ«${big}»`;
    sellTopLbl.textContent = `سعر بيع الـ«${big}»`;
    buyBaseLbl.textContent = `سعر شراء الـ«${small}»`;
    sellBaseLbl.textContent= `سعر بيع الـ«${small}»`;
    buyBaseView.textContent = `${fmt(buyBase)} ${cur()}`;
    sellTopView.textContent = `${fmt(sellBase * bf)} ${cur()}`;
    prevBox.innerHTML = '';
        f.units.forEach((u, i) => {
      prevBox.append(h('span', { class: 'price-chip' }, `${u.name}:`,
        h('b', {}, `شراء ${fmt(buyBase * unitF(i))} • بيع ${fmt(sellBase * unitF(i))}`)));
    });
  }
  buyInp.addEventListener('input', syncFromPct);
  pctInp.addEventListener('input', syncFromPct);
  sellInp.addEventListener('input', syncFromSell);
  function drawStockUnit() {
    stockUnit.innerHTML = '';
    f.units.forEach((u, i) => stockUnit.append(h('option', { value: i }, u.name)));
  }
  if (existing) { stockInp.value = ''; stockInp.placeholder = 'اتركه فارغاً لعدم التغيير'; }

  /* مميز */
  const featSw = h('div', { class: 'lux-switch' + (f.featured ? ' on' : ''), onclick: () => { f.featured = !f.featured; featSw.classList.toggle('on', f.featured); } },
    h('span', { class: 'sw' }), h('div', {}, h('b', {}, 'صنف مميز'), h('small', {}, 'يظهر في تبويب المميز بنقطة البيع للوصول السريع')));

  grid.append(
        h('div', { class: 'f-field' }, h('label', {}, 'اسم البراند ', h('span', { class: 'req' }, '*')), nameInp),
    h('div', { class: 'f-field' }, h('label', {}, 'الاسم العلمي (اختياري)'), sciInp),
    h('div', { class: 'f-field' }, h('label', {}, 'الشركة المصنعة ', h('span', { class: 'req' }, '*')), h('div', { style: { position: 'relative' } }, compInp, compSug)),
    h('div', { class: 'f-field' }, h('label', {}, 'البلد المصنع (اختياري)'), countryInp, countryList),
    h('div', { class: 'f-field full' }, h('label', {}, 'الباركودات (يمكن إضافة عدد لا نهائي)'),
      h('div', { class: 'input-group' }, bcInp,
        h('button', { class: 'btn n', onclick: () => addBarcode(bcInp.value) }, h('span', { html: icon('plus') }), 'إضافة'),
        h('button', { class: 'btn b', onclick: () => { const c = genBarcode(); f.barcodes.push(c); drawBarcodes(); toast(`باركود مولّد: ${c}`, 'b'); } }, h('span', { html: icon('barcode') }), 'توليد')),
      bcList),
    h('div', { class: 'f-field' }, h('label', {}, 'الشكل العلاجي'), formSel),
    h('div', { class: 'f-field' }, h('label', {}, 'الجرعة'), h('div', { class: 'input-group' }, doseInp, doseUnit)),
    h('div', { class: 'f-field' }, h('label', {}, 'تاريخ الانتهاء'), expiryInp),
    h('div', { class: 'f-field' }, h('label', {}, `جرد افتتاحي ${existing ? '(إضافة للمخزون الحالي)' : '(اختياري)'}`), h('div', { class: 'input-group' }, stockInp, stockUnit)),
    h('div', { class: 'f-field full' }, featSw),
    h('div', { class: 'f-field full' }, h('label', {}, 'التعبئة والوحدات ', h('span', { class: 'req' }, '*')), packBox),
        h('div', { class: 'f-field full' }, h('label', {}, 'الأسعار ', h('span', { class: 'req' }, '*'), h('span', { class: 'f-hint' }, ' — عناوين الخلايا تتسمّى تلقائياً حسب وحداتك')),
      h('div', { class: 'price-quad' },
        h('div', { class: 'pq-cell edit' }, buyTopLbl, buyInp),
        h('div', { class: 'pq-cell' }, sellTopLbl, h('div', { class: 'pq-view' }, sellTopView)),
        h('div', { class: 'pq-cell' }, buyBaseLbl, h('div', { class: 'pq-view' }, buyBaseView)),
        h('div', { class: 'pq-cell edit' }, sellBaseLbl,
          h('div', { class: 'input-group' }, sellInp, h('span', { class: 'pq-side' }, 'ربح'), pctInp, h('span', { class: 'pq-side' }, '%'))))),
    h('div', { class: 'f-field full' }, h('label', {}, 'معاينة الأسعار لكل وحدة'), prevBox),
  );

  page.append(grid, h('div', { style: { display: 'flex', gap: '10px', marginTop: '6px', paddingBottom: '14px' } },
    h('button', { class: 'btn g big', onclick: saveIt }, h('span', { html: icon('check') }), existing ? 'حفظ التعديلات' : 'حفظ الصنف'),
    h('button', { class: 'btn n', onclick: () => closeTab(tab.id) }, 'إلغاء')));

    async function saveIt() {
    const name = nameInp.value.trim();
    if (!name) return toast('أدخل اسم البراند', 'r');
    f.company = compInp.value.trim();
    if (!f.company) return toast('أدخل الشركة المصنعة', 'r');
    f.country = countryInp.value.trim();
    if (!companies.some(c => c.name === f.company)) { // شركة مكتوبة يدوياً → تُسجَّل وتُزامَن مع الإعدادات
      companies.push({ name: f.company, country: f.country || '' });
      await save('settings', state.settings);
    } else {
      const ex = companies.find(c => c.name === f.company);
      if (ex && f.country && ex.country !== f.country) { ex.country = f.country; await save('settings', state.settings); }
    }
    if (!f.barcodes.length) f.barcodes.push(genBarcode());
    if (!num(buyInp.value)) return toast('أدخل سعر الشراء', 'r');
    if (!num(sellInp.value)) return toast('أدخل سعر البيع', 'r');
    f.brandName = name; f.scientificName = sciInp.value.trim();
    f.form = formSel.value === '__add' ? f.form : formSel.value;
    f.dose = doseInp.value ? `${doseInp.value}${doseUnit.value}` : '';
    f.expiry = expiryInp.value;
    f.purchasePriceTop = num(buyInp.value);
    f.salePriceBase = num(sellInp.value);
    f.units = f.units.filter(u => u.name.trim());
    if (existing) {
      const addStock = num(stockInp.value);
      if (addStock) f.stockBase = (existing.stockBase || 0) + addStock * unitF(+stockUnit.value || 0);
      else f.stockBase = existing.stockBase || 0;
      f.id = existing.id; f.createdAt = existing.createdAt;
    } else {
      f.id = uid(); f.createdAt = Date.now();
      f.stockBase = num(stockInp.value) * unitF(+stockUnit.value || 0);
    }
    await save('products', f);
    toast(existing ? 'تم حفظ التعديلات' : `تمت إضافة «${f.brandName}»`);
    if (P.returnTab) {
      const rt = tabs.find(t => t.id === P.returnTab);
      if (rt && rt.type === 'purchase') {
        addPurchaseItem(rt, f, 1);
        closeTab(tab.id); activateTab(rt.id); renderSideNav(); return;
      }
    }
    if (P.onSavedGo) { closeTab(tab.id); openTab(P.onSavedGo); renderSideNav(); return; }
    if (existing) closeTab(tab.id); else { tab.state.form = null; renderTabContent(tab); }
    renderSideNav();
  }
  tab.el.append(page);
  drawPack(); drawStockUnit(); drawBarcodes(); drawPricePreview();
  setTimeout(() => nameInp.focus(), 80);
}

/* ───────────────────────── 15) قائمة الشراء ───────────────────────── */
function renderPurchase(tab) {
  const st = tab.state;
  st.items = st.items || [];  // [{productId,name,unitIdx,qty,buyPrice,expiry}]
  st.discount = st.discount || 0;
  const page = h('div', { class: 'pos-layout' });
  const center = h('div', { class: 'pos-center' });

  /* رأس القائمة: المذخر + رقم القائمة */
  const supSel = h('select', {}, h('option', { value: '' }, '— اختر المذخر —'),
    state.suppliers.filter(s => !s.deleted).map(s => h('option', { value: s.id, selected: st.supplierId === s.id }, s.name)));
  supSel.addEventListener('change', () => st.supplierId = supSel.value || null);
  const listNum = h('input', { value: st.listNum || (state.purchases.length + 1), type: 'number', min: 1, style: { width: '110px' } });
  listNum.addEventListener('change', () => st.listNum = num(listNum.value));
  center.append(h('div', { class: 'filter-bar' },
    h('div', { class: 'f-group' }, h('label', {}, 'اسم المذخر'), supSel,
            h('button', { class: 'icon-btn edit', title: 'إضافة مذخر', html: icon('plus'), onclick: () => openAddSupplierModal(() => renderTabContent(tab)) })),
    h('div', { class: 'f-group' }, h('label', {}, 'رقم القائمة'), listNum),
    h('div', { class: 'spacer' }),
    h('button', { class: 'mini-btn blue', style: { flex: 'none', padding: '8px 16px' }, onclick: () => openTab('scanner', { returnTab: tab.id }) },
      h('span', { html: icon('camera') }), 'قراءة فاتورة ورقية بالصورة')));

  /* محرك البحث / الباركود */
  const sInput = h('input', { placeholder: 'أدخل باركود الصنف أو ابحث بالاسم…', autocomplete: 'off' });
  const sugBox = h('div', { class: 'suggestions' });
  let sugItems = [];
  sInput.addEventListener('input', () => {
    const q = sInput.value;
    sugItems = searchProducts(q);
    sugBox.innerHTML = '';
    if (!q.trim()) { sugBox.classList.remove('show'); return; }
    if (!sugItems.length) sugBox.append(h('div', { class: 'sug-empty' }, 'غير موجود — اضغط Enter لإضافته كصنف جديد'));
    else sugItems.forEach(p => sugBox.append(h('div', { class: 'sug-item', onclick: () => pick(p) },
      h('span', { class: 'sug-ic', html: icon('pill') }),
      h('div', { class: 'sug-name' }, p.brandName, coTag(p), h('small', {}, `${p.form || ''} ${p.dose || ''}`)),
      h('span', { class: 'sug-price' }, `شراء ${fmt(costPerUnit(p, 0))} / ${bigUnitName(p)}`))));
    sugBox.classList.add('show');
  });
  sInput.addEventListener('keydown', async e => {
    if (e.key !== 'Enter') return;
    const q = sInput.value.trim();
    if (!q) return;
    const exact = state.products.find(p => !p.deleted && (p.barcodes || []).some(b => b === q));
    if (exact) pick(exact);
    else if (sugItems.length === 1) pick(sugItems[0]);
    else {
      sugBox.classList.remove('show');
      const yes = await confirmBox(`الصنف «${q}» غير متوفر في النظام. هل تريد إدخاله؟`, { okLabel: 'نعم، إدخاله', icon: 'plus' });
      if (yes) openTab('product', { barcode: q, returnTab: tab.id, supplierId: st.supplierId });
    }
  });
  function pick(p) {
    addPurchaseItem(tab, p, 1);
    sInput.value = ''; sugBox.classList.remove('show'); sInput.focus();
  }
  center.append(h('div', { class: 'search-engine' },
    h('div', { class: 'search-box' }, h('span', { html: icon('barcode') }), sInput,
      h('span', { class: 'search-hint' }, 'باركود ← إدخال مباشر')), sugBox));

  /* جدول الأصناف */
  const cartWrap = h('div', { class: 'cart-wrap' });
  st.renderItems = () => {
    cartWrap.innerHTML = '';
    if (!st.items.length) {
      cartWrap.append(h('div', { class: 'cart-empty' }, h('span', { html: icon('purchase') }), h('p', {}, 'أدخل باركود الأصناف لبناء قائمة الشراء')));
      return;
    }
    const tbody = h('tbody');
    st.items.forEach((it, i) => {
      const p = findProd(it.productId);
      tbody.append(h('tr', {},
        h('td', { class: 'td-seq' }, i + 1),
        h('td', { class: 'td-name' }, it.name, h('small', {}, p ? `${p.form || ''} ${p.dose || ''}` : '')),
        h('td', {}, p ? (() => {
          const sel = h('select', { class: 'unit-select' }, p.units.map((u, ui) => h('option', { value: ui, selected: ui === it.unitIdx }, u.name)));
          sel.addEventListener('change', () => { it.unitIdx = +sel.value; it.buyPrice = Math.round(costPerUnit(p, it.unitIdx) * 100) / 100; st.renderItems(); drawTotals(); });
          return sel;
        })() : it.unitName || ''),
        h('td', {}, (() => {
          const q = h('input', { type: 'number', value: it.qty, min: 1, style: { width: '70px', border: '1px solid var(--line)', borderRadius: '8px', padding: '5px', textAlign: 'center', fontWeight: 900 } });
          q.addEventListener('change', () => { it.qty = Math.max(1, num(q.value) || 1); drawTotals(); });
          return q;
        })()),
        h('td', {}, (() => {
          const pr = h('input', { type: 'number', value: it.buyPrice, min: 0, style: { width: '90px', border: '1px solid var(--line)', borderRadius: '8px', padding: '5px', textAlign: 'center', fontWeight: 900 } });
          pr.addEventListener('change', () => { it.buyPrice = num(pr.value); drawTotals(); });
          return pr;
        })()),
        h('td', {}, (() => {
          const ex = h('input', { type: 'month', value: it.expiry || (p ? p.expiry : '') || '', style: { border: '1px solid var(--line)', borderRadius: '8px', padding: '4px 6px', fontWeight: 800, fontSize: '12.5px' } });
          ex.addEventListener('change', () => it.expiry = ex.value);
          return ex;
        })()),
        h('td', { class: 'td-num td-total' }, fmt(it.buyPrice * it.qty)),
        h('td', {}, h('button', { class: 'icon-btn del', html: icon('trash'), onclick: () => { st.items.splice(i, 1); st.renderItems(); drawTotals(); } })),
      ));
    });
    cartWrap.append(h('div', { class: 'tbl-scroll' },
      h('table', { class: 'tbl' },
        h('thead', {}, h('tr', {}, h('th', {}, 'ت'), h('th', {}, 'المنتج'), h('th', {}, 'الوحدة'), h('th', {}, 'العدد'), h('th', {}, 'سعر الشراء'), h('th', {}, 'الإكسباير'), h('th', {}, 'المجموع'), h('th', {}, 'حذف'))),
        tbody)));
  };

  /* التذييل */
  const totalEl = h('div', { class: 'tval' }, h('span', {}, '0'), ' ', h('small', {}, cur()));
  const discInp = h('input', { type: 'number', min: 0, placeholder: '0', value: st.discount || '' });
  discInp.addEventListener('input', () => { st.discount = num(discInp.value); drawTotals(); });
  function drawTotals() {
    const t = st.items.reduce((s, it) => s + it.buyPrice * it.qty, 0);
    totalEl.firstChild.textContent = fmt(Math.max(0, t - st.discount));
  }
  const footer = h('div', { class: 'pos-footer' },
    h('div', { class: 'totals-row' },
      h('div', { class: 'total-card' }, h('label', {}, 'خصم القائمة'), h('div', { class: 'discount-wrap' }, discInp)),
      h('div', { class: 'total-card grand' }, h('label', {}, 'إجمالي قائمة الشراء'), totalEl)),
    h('div', { class: 'pay-row' },
      h('button', { class: 'pay-btn cash', onclick: () => savePurchaseModal(tab) }, h('span', { html: icon('check') }), 'حفظ قائمة الشراء')));

  center.append(cartWrap);
  /* الجانب: قوائم الشراء السابقة */
  const side = h('div', { class: 'pos-side' });
  side.append(h('div', { class: 'side-tabs' }, h('div', { class: 'side-tab active' }, 'قوائم الشراء السابقة')));
  const sideBody = h('div', { class: 'side-body' });
    state.purchases.filter(p => p.type === 'return' && !p.deleted).sort((a, b) => b.ts - a.ts).slice(0, 30).forEach(pu =>
    sideBody.append(h('div', { class: 'inv-mini', onclick: () => openTab('editpurch', { purchaseId: pu.id, readonly: true }) },
      h('div', { class: 'im-top' }, h('span', {}, pu.supplierName), h('b', {}, `${fmt(pu.total)} ${cur()}`)),
      h('div', { class: 'im-sub' }, h('span', {}, `قائمة رقم ${pu.listNum} • ${fmtDate(pu.ts)}`),
        h('span', { class: 'badge ' + (pu.pay === 'cash' ? 'g' : 'r') }, pu.pay === 'cash' ? 'كاش' : 'آجل')))));
  if (!sideBody.children.length) sideBody.append(h('div', { class: 'empty-note' }, 'لا قوائم شراء سابقة'));
  side.append(sideBody);
  page.append(h('div', { style: { flex: 1, display: 'flex', minHeight: 0 } }, center, side), footer);
  tab.el.append(page);
  st.renderItems(); drawTotals();
  setTimeout(() => sInput.focus(), 60);
}
function addPurchaseItem(tab, p, qty = 1) {
  const st = tab.state;
  st.items = st.items || [];
  const ex = st.items.find(it => it.productId === p.id && it.unitIdx === 0);
  if (ex) ex.qty += qty;
  else st.items.push({ productId: p.id, name: p.brandName, unitIdx: 0, qty, buyPrice: costPerUnit(p, 0), expiry: p.expiry || '' });
  if (st.renderItems) { st.renderItems(); }
  toast(`أُضيف «${p.brandName}» للقائمة`, 'b');
}
async function savePurchaseModal(tab) {
  const st = tab.state;
  if (!st.items || !st.items.length) return toast('القائمة فارغة', 'r');
  if (!st.supplierId) return toast('اختر المذخر أولاً', 'r');
  const sup = findSup(st.supplierId);
  const total = st.items.reduce((s, it) => s + it.buyPrice * it.qty, 0);
  const discPctInp = h('input', { type: 'number', min: 0, max: 100, value: total ? Math.round(st.discount / total * 1000) / 10 : 0, style: { width: '90px' } });
  const m = openModal({
    title: 'طريقة تسديد قائمة الشراء', icon: 'cash',
    body: h('div', {},
      h('div', { class: 'sum-card n', style: { marginBottom: '14px' } }, h('label', {}, `إجمالي القائمة للمذخر «${sup.name}»`), h('b', {}, `${fmt(total)} ${cur()}`)),
      h('div', { class: 'f-field' }, h('label', {}, 'خصم المذخر (نسبة %)'), h('div', { class: 'input-group' }, discPctInp,
        h('span', { style: { alignSelf: 'center', fontWeight: 900 } }, `% ≈ ${fmt(total * num(discPctInp.value) / 100)} ${cur()}`)))),
    actions: [
      { label: 'إلغاء', cls: 'n', onClick: c => c() },
      { label: 'آجل (دين متراكم)', cls: 'r', icon: 'clock', big: true, onClick: c => { c(); finalizePurchase(tab, 'credit', total * num(discPctInp.value) / 100); } },
      { label: 'كاش مباشر', cls: 'g', icon: 'cash', big: true, onClick: c => { c(); finalizePurchase(tab, 'cash', total * num(discPctInp.value) / 100); } },
    ],
  });
}
async function finalizePurchase(tab, pay, discount) {
  const st = tab.state;
  const sup = findSup(st.supplierId);
  const acc = me();
  const ts = Date.now();
  const items = st.items.map(it => {
    const p = findProd(it.productId);
    return { ...it, unitName: p ? p.units[it.unitIdx].name : '', qtyBase: p ? it.qty * unitFactor(p, it.unitIdx) : it.qty, total: it.buyPrice * it.qty };
  });
  const total = Math.max(0, items.reduce((s, it) => s + it.total, 0) - discount);
  if (pay === 'credit') sup.debt = (sup.debt || 0) + total;
  sup.lastPurchase = { amount: total, ts };
  const pu = {
    id: uid(), type: 'purchase', version: 1, versions: [],
    supplierId: sup.id, supplierName: sup.name, listNum: st.listNum || (state.purchases.length + 1),
    items, discount, total, pay, debtAfter: sup.debt || 0,
    employeeId: acc.id, employeeName: acc.name,
    ts, date: dateStr(ts), time: timeStr(ts), deviceId: DEVICE_ID,
  };
  await save('purchases', pu);
  await save('suppliers', sup);
  for (const it of items) {  // رفع المخزون + تحديث سعر الشراء والإكسباير
    const p = findProd(it.productId);
    if (p) {
      p.stockBase = (p.stockBase || 0) + it.qtyBase;
      if (it.unitIdx === 0 && it.buyPrice) p.purchasePriceTop = it.buyPrice;
      if (it.expiry) p.expiry = it.expiry;
      await save('products', p);
    }
  }
  st.items = []; st.discount = 0; st.listNum = null; st.supplierId = null;
  renderTabContent(tab);
  renderSideNav();
  toast(`حُفظت قائمة الشراء — ${fmt(total)} ${cur()} ${pay === 'credit' ? '(دين متراكم)' : '(كاش)'}`);
}

/* ───────────────────────── 16) تقرير المبيعات ───────────────────────── */
function renderSalesReport(tab) {
  const st = tab.state;
    st.f = st.f || { customer: '', employee: me() ? me().id : '', from: dateStr(), to: dateStr(), type: '', sortKey: 'ts', sortDir: 1 }; // يفتح على اليوم مباشرة — غيّر من/إلى لأي فترة
  const page = h('div', { class: 'page' });
  page.append(h('div', { class: 'page-head' }, h('div', { class: 'page-title' }, h('span', { html: icon('report') }), 'تقرير المبيعات')));

  /* الفلاتر */
  const custSel = h('select', {}, h('option', { value: '' }, 'الكل'), state.customers.map(c => h('option', { value: c.id, selected: st.f.customer === c.id }, c.name)));
  custSel.addEventListener('change', () => { st.f.customer = custSel.value; draw(); });
  const empSel = h('select', {}, h('option', { value: '' }, 'الكل'),
    state.accounts.filter(a => !a.deleted).map(a => h('option', { value: a.id, selected: st.f.employee === a.id }, a.name)));
  empSel.addEventListener('change', () => { st.f.employee = empSel.value; draw(); });
  const fromI = h('input', { type: 'date', value: st.f.from });
  const toI = h('input', { type: 'date', value: st.f.to });
  fromI.addEventListener('change', () => { st.f.from = fromI.value; draw(); });
  toI.addEventListener('change', () => { st.f.to = toI.value; draw(); });
  const typeSel = h('select', {},
    h('option', { value: '' }, 'الكل'), h('option', { value: 'sale' }, 'بيع'), h('option', { value: 'return' }, 'استرجاع بيع'));
  typeSel.value = st.f.type;
  typeSel.addEventListener('change', () => { st.f.type = typeSel.value; draw(); });
  page.append(h('div', { class: 'filter-bar' },
    h('div', { class: 'f-group' }, h('label', {}, 'الزبون'), custSel),
    h('div', { class: 'f-group' }, h('label', {}, 'الموظف'), empSel),
    h('div', { class: 'f-group' }, h('label', {}, 'من'), fromI, h('label', {}, 'إلى'), toI),
    h('div', { class: 'f-group' }, h('label', {}, 'نوع العملية'), typeSel)));

  const bodyBox = h('div', { class: 'page-body' });
  const footBox = h('div', { class: 'page-footer' });
  page.append(bodyBox, footBox);

  const COLS = [
    ['type', 'نوع العملية'], ['employeeName', 'الموظف'], ['customerName', 'الزبون'],
    ['date', 'التاريخ'], ['time', 'الوقت'], ['pay', 'نوع الدفع'], ['cost', 'التكلفة'],
    ['subtotal', 'البيع'], ['profit', 'الربح'], ['discount', 'الخصم'], ['net', 'صافي البيع'], [null, 'تعديل'],
  ];
    function filtered() {
    return state.purchases.filter(p => !p.deleted &&
      (!st.f.supplier || p.supplierId === st.f.supplier) && (!st.f.employee || p.employeeId === st.f.employee) &&
      (!st.f.from || p.date >= st.f.from) && (!st.f.to || p.date <= st.f.to) && (!st.f.type || p.type === st.f.type)
    ).sort((a, b) => {
      const k = st.f.sortKey;
      let va = a[k], vb = b[k];
      if (typeof va === 'string') return va.localeCompare(vb, 'ar') * st.f.sortDir;
      return ((va || 0) - (vb || 0)) * st.f.sortDir;
    });
  }
  function draw() {
    const rows = filtered();
    bodyBox.innerHTML = '';
    const thead = h('tr', {}, COLS.map(([k, label]) =>
      h('th', { class: k ? 'sortable' : '', onclick: k ? () => { if (st.f.sortKey === k) st.f.sortDir *= -1; else { st.f.sortKey = k; st.f.sortDir = -1; } draw(); } : null },
        label, st.f.sortKey === k ? h('span', { class: 'sort-arw' }, st.f.sortDir === -1 ? ' ▼' : ' ▲') : null)));
    const tbody = h('tbody');
    rows.forEach(s => tbody.append(h('tr', {},
      h('td', {}, h('span', { class: 'badge ' + (s.type === 'sale' ? 'g' : 'r') }, s.type === 'sale' ? 'بيع' : 'استرجاع'),
        s.version > 1 ? h('span', { class: 'badge n', title: 'عدد التعديلات' }, `ع${s.version}`) : null),
      h('td', {}, s.employeeName), h('td', {}, s.customerName || 'زبون نقدي'),
      h('td', { class: 'mono' }, fmtDate(s.ts)), h('td', { class: 'mono' }, fmtTime(s.ts)),
      h('td', {}, h('span', { class: 'badge ' + (s.pay === 'cash' ? 'g' : s.pay === 'electronic' ? 'b' : 'r') },
        s.pay === 'cash' ? 'كاش' : s.pay === 'electronic' ? 'إلكتروني' : 'آجل')),
      h('td', { class: 'td-num td-cost' }, fmt(s.cost)),
      h('td', { class: 'td-num td-sale' }, fmt(s.subtotal)),
      h('td', { class: 'td-num', style: { color: s.profit >= 0 ? 'var(--green)' : 'var(--red)' } }, fmt(s.profit)),
      h('td', { class: 'td-num', style: { color: 'var(--red)' } }, fmt(s.discount)),
      h('td', { class: 'td-num td-total', style: { fontSize: '16px' } }, fmt(s.net)),
      h('td', {}, h('button', { class: 'icon-btn edit', title: 'تعديل القائمة', html: icon('edit'), onclick: () => openTab('editsale', { saleId: s.id }) })),
    )));
    bodyBox.append(h('div', { class: 'tbl-scroll' }, h('table', { class: 'tbl' }, h('thead', {}, thead), tbody)));
    if (!rows.length) bodyBox.append(h('div', { class: 'empty-note' }, 'لا نتائج ضمن الفلاتر المحددة'));

    /* الإجماليات — الإلكتروني منفصل، الآجل خارج الدخل */
    const sales = rows.filter(s => s.type === 'sale'), rets = rows.filter(s => s.type === 'return');
    const cashNet = sales.filter(s => s.pay === 'cash').reduce((x, s) => x + s.net, 0) - rets.filter(s => s.pay === 'cash').reduce((x, s) => x + s.net, 0);
    const elecNet = sales.filter(s => s.pay === 'electronic').reduce((x, s) => x + s.net, 0) - rets.filter(s => s.pay === 'electronic').reduce((x, s) => x + s.net, 0);
    const credNet = sales.filter(s => s.pay === 'credit').reduce((x, s) => x + s.net, 0) - rets.filter(s => s.pay === 'credit').reduce((x, s) => x + s.net, 0);
    const tCost = rows.reduce((x, s) => x + (s.type === 'sale' ? s.cost : -s.cost), 0);
    const tSale = rows.reduce((x, s) => x + (s.type === 'sale' ? s.subtotal : -s.subtotal), 0);
        const tDisc = rows.reduce((x, s) => x + s.discount, 0);
    const tRet = rets.reduce((x, s) => x + s.net, 0);
    footBox.innerHTML = '';
    footBox.append(
            h('div', { class: 'sum-card n' }, h('label', {}, 'التكلفة الكلية'), h('b', {}, fmt(tCost))),
      h('div', { class: 'sum-card r' }, h('label', {}, 'مجموع المرتجعات'), h('b', {}, fmt(tRet))),
      h('div', { class: 'sum-card b' }, h('label', {}, 'البيع الكلي (قبل الخصم)'), h('b', {}, fmt(tSale))),
      h('div', { class: 'sum-card r' }, h('label', {}, 'الخصم الكلي'), h('b', {}, fmt(tDisc))),
      h('div', { class: 'sum-card g' }, h('label', {}, 'كاش'), h('b', {}, fmt(cashNet))),
      h('div', { class: 'sum-card b' }, h('label', {}, 'إلكتروني (منفصل)'), h('b', {}, fmt(elecNet))),
      h('div', { class: 'sum-card r' }, h('label', {}, 'آجل (خارج الدخل)'), h('b', {}, fmt(credNet))),
      h('div', { class: 'sum-card big' }, h('label', {}, 'صافي الدخل (كاش + إلكتروني)'), h('b', {}, `${fmt(cashNet + elecNet)} ${cur()}`)));
  }
  draw();
  tab.el.append(page);
}

/* ───────────────────────── 17) تعديل قائمة بيع (نظام النسخ) ───────────────────────── */
function renderEditSale(tab) {
  const sale = state.sales.find(s => s.id === tab.props.saleId);
  if (!sale) { tab.el.append(h('div', { class: 'empty-note' }, 'القائمة غير موجودة')); return; }
  const st = tab.state;
  st.viewVer = st.viewVer || sale.version; // الافتراضي: آخر نسخة
  const isLatest = st.viewVer === sale.version;
  const snap = isLatest ? sale : sale.versions[st.viewVer - 1];
  if (!st.editItems || st.savedFor !== sale.version) {
    st.editItems = JSON.parse(JSON.stringify(snap.items));
    st.discount = snap.discount;
    st.pay = snap.pay; st.customerId = snap.customerId;
    st.savedFor = null;
  }
  const page = h('div', { class: 'page' });
  page.append(h('div', { class: 'page-head' },
    h('div', { class: 'page-title' }, h('span', { html: icon('edit') }),
      `تعديل قائمة بيع — ${fmtDate(sale.ts)} ${fmtTime(sale.ts)}`),
    h('span', { class: 'badge n' }, `الموظف الأصلي: ${sale.employeeName}`),
    h('div', { class: 'spacer' }),
    h('div', { class: 'ver-pills' },
      h('span', { class: 'ver-note' }, 'النسخة:'),
      ...Array.from({ length: sale.version }, (_, i) => i + 1).map(v =>
        h('button', { class: 'ver-pill' + (v === st.viewVer ? ' cur' : ''), onclick: () => { st.viewVer = v; st.savedFor = null; renderTabContent(tab); } }, v)))),
  );
  if (!isLatest)
    page.append(h('div', { class: 'readonly-banner' }, h('span', { html: icon('lock') }),
      `أنت تعرض النسخة رقم ${st.viewVer} (قراءة فقط) — التعديل يتم دائماً على آخر نسخة (رقم ${sale.version})`));

  const center = h('div', { class: 'pos-center', style: { padding: 0 } });
  if (isLatest) {
    const sInput = h('input', { placeholder: 'أضف صنفاً للقائمة…', autocomplete: 'off' });
    const sugBox = h('div', { class: 'suggestions' });
    let sugItems = [];
    sInput.addEventListener('input', () => {
      sugItems = searchProducts(sInput.value);
      sugBox.innerHTML = '';
      if (!sInput.value.trim()) { sugBox.classList.remove('show'); return; }
      sugItems.forEach(p => sugBox.append(h('div', { class: 'sug-item', onclick: () => {
        st.editItems.push({ productId: p.id, name: p.brandName, unitIdx: p.units.length - 1, unitName: p.units[p.units.length - 1].name, qty: 1, cost: costPerUnit(p, p.units.length - 1), sale: salePerUnit(p, p.units.length - 1) });
        sInput.value = ''; sugBox.classList.remove('show'); drawItems(); drawTotals();
      } }, h('span', { class: 'sug-ic', html: icon('pill') }), h('div', { class: 'sug-name' }, p.brandName, coTag(p)), h('span', { class: 'sug-price' }, fmt(salePerUnit(p, p.units.length - 1))))));
      sugBox.classList.toggle('show', !!sugItems.length);
    });
    center.append(h('div', { class: 'search-engine' }, h('div', { class: 'search-box' }, h('span', { html: icon('search') }), sInput), sugBox));
  }
  const itemsBox = h('div', { class: 'cart-wrap', style: { flex: 'none', maxHeight: '46vh' } });
  function drawItems() {
    itemsBox.innerHTML = '';
    const tbody = h('tbody');
    st.editItems.forEach((it, i) => {
      const p = findProd(it.productId);
      tbody.append(h('tr', {},
        h('td', { class: 'td-seq' }, i + 1),
        h('td', { class: 'td-name' }, it.name),
        h('td', {}, isLatest && p ? (() => {
          const sel = h('select', { class: 'unit-select' }, p.units.map((u, ui) => h('option', { value: ui, selected: ui === it.unitIdx }, u.name)));
          sel.addEventListener('change', () => { it.unitIdx = +sel.value; it.sale = salePerUnit(p, it.unitIdx); it.cost = costPerUnit(p, it.unitIdx); drawItems(); drawTotals(); });
          return sel;
        })() : (it.unitName || '')),
        h('td', {}, isLatest ? (() => {
          const q = h('input', { type: 'number', value: it.qty, min: 0.5, style: { width: '70px', border: '1px solid var(--line)', borderRadius: '8px', padding: '5px', textAlign: 'center', fontWeight: 900 } });
          q.addEventListener('change', () => { it.qty = Math.max(0.5, num(q.value) || 1); drawTotals(); });
          return q;
        })() : fmt(it.qty)),
        h('td', { class: 'td-num td-sale' }, fmt(it.sale)),
        h('td', { class: 'td-num td-total' }, fmt(it.sale * it.qty)),
        isLatest ? h('td', {}, h('button', { class: 'icon-btn del', html: icon('trash'), onclick: () => { st.editItems.splice(i, 1); drawItems(); drawTotals(); } })) : h('td', {}, ''),
      ));
    });
    itemsBox.append(h('div', { class: 'tbl-scroll' }, h('table', { class: 'tbl' },
      h('thead', {}, h('tr', {}, h('th', {}, 'ت'), h('th', {}, 'المنتج'), h('th', {}, 'الوحدة'), h('th', {}, 'العدد'), h('th', {}, 'سعر البيع'), h('th', {}, 'المجموع'), h('th', {}, ''))), tbody)));
  }
  const netEl = h('b', {}, '0');
  const discInp = h('input', { type: 'number', min: 0, value: st.discount, disabled: !isLatest, style: { width: '100px', border: '1.5px solid var(--line)', borderRadius: '10px', padding: '7px', fontWeight: 900, textAlign: 'center' } });
  discInp.addEventListener('input', () => { st.discount = num(discInp.value); drawTotals(); });
  const paySel = h('select', { class: 'unit-select', disabled: !isLatest },
    h('option', { value: 'cash', selected: st.pay === 'cash' }, 'كاش'),
    h('option', { value: 'electronic', selected: st.pay === 'electronic' }, 'إلكتروني'),
    h('option', { value: 'credit', selected: st.pay === 'credit' }, 'آجل'));
  paySel.addEventListener('change', () => st.pay = paySel.value);
  const custSel = h('select', { class: 'unit-select', disabled: !isLatest },
    h('option', { value: '' }, 'زبون نقدي'), state.customers.map(c => h('option', { value: c.id, selected: st.customerId === c.id }, c.name)));
  custSel.addEventListener('change', () => st.customerId = custSel.value || null);
  function drawTotals() {
    const sub = st.editItems.reduce((s, it) => s + it.sale * it.qty, 0);
    netEl.textContent = `${fmt(Math.max(0, sub - st.discount))} ${cur()}`;
  }
  center.append(itemsBox,
    h('div', { class: 'filter-bar', style: { marginTop: '12px' } },
      h('div', { class: 'f-group' }, h('label', {}, 'الخصم'), discInp),
      h('div', { class: 'f-group' }, h('label', {}, 'نوع الدفع'), paySel),
      h('div', { class: 'f-group' }, h('label', {}, 'الزبون'), custSel),
      h('div', { class: 'spacer' }),
      h('div', { class: 'f-group' }, h('label', {}, 'الصافي بعد التعديل'), netEl)));
  if (isLatest) {
    center.append(h('div', { style: { display: 'flex', gap: '10px', marginTop: '12px' } },
      h('button', { class: 'btn g big', onclick: saveEdit }, h('span', { html: icon('check') }), 'حفظ التعديل (نسخة جديدة)'),
      sale.type === 'sale' ? h('button', { class: 'btn r', onclick: makeReturn }, h('span', { html: icon('refresh') }), 'استرجاع القائمة كاملة') : null));
  }
  page.append(center);
  tab.el.append(page);
  drawItems(); drawTotals();

  async function saveEdit() {
    if (!st.editItems.length) return toast('لا يمكن حفظ قائمة فارغة', 'r');
    // 1) خزّن النسخة الحالية في الأرشيف (لا تُمحى أبداً)
    sale.versions.push({ items: JSON.parse(JSON.stringify(sale.items)), subtotal: sale.subtotal, discount: sale.discount, net: sale.net, cost: sale.cost, profit: sale.profit, pay: sale.pay, customerId: sale.customerId, customerName: sale.customerName });
    // 2) صحّح المخزون: أعد القديم ثم اخصم الجديد
    for (const it of sale.items) { const p = findProd(it.productId); if (p) { p.stockBase = (p.stockBase || 0) + it.qtyBase; } }
    const items = st.editItems.map(it => {
      const p = findProd(it.productId);
      return { ...it, unitName: p ? p.units[it.unitIdx].name : it.unitName, qtyBase: p ? it.qty * unitFactor(p, it.unitIdx) : it.qty, total: it.sale * it.qty };
    });
    for (const it of items) { const p = findProd(it.productId); if (p) { p.stockBase = (p.stockBase || 0) - it.qtyBase; await save('products', p); } }
    // 3) حدّث القائمة (نفس الوقت والتاريخ والموقع)
    sale.items = items;
    sale.subtotal = items.reduce((s, it) => s + it.total, 0);
    sale.discount = st.discount;
    sale.net = Math.max(0, sale.subtotal - st.discount);
    sale.cost = items.reduce((s, it) => s + it.cost * it.qty, 0);
    sale.profit = sale.net - sale.cost;
    sale.pay = st.pay;
    sale.customerId = st.customerId;
    sale.customerName = st.customerId ? (findCust(st.customerId) || {}).name : 'زبون نقدي';
    sale.version += 1;
    sale.editedBy = me().name; sale.editedAt = Date.now();
    await save('sales', sale);
    st.savedFor = sale.version;
    toast(`حُفظت النسخة ${sale.version} — القائمة بقت بوقتها الأصلي`);
    closeTab(tab.id);
  }
  async function makeReturn() {
    const yes = await confirmBox('سيتم إنشاء قائمة استرجاع كاملة لهذه الفاتورة وإعادة الأصناف للمخزون. متابعة؟', { danger: true, okLabel: 'استرجاع', icon: 'refresh' });
    if (!yes) return;
    const ts = Date.now();
    const acc = me();
    const ret = {
      id: uid(), type: 'return', version: 1, versions: [], originalId: sale.id,
      items: JSON.parse(JSON.stringify(sale.items)), subtotal: sale.subtotal, discount: sale.discount,
      net: sale.net, cost: sale.cost, profit: -sale.profit,
      pay: sale.pay, customerId: sale.customerId, customerName: sale.customerName,
      employeeId: acc.id, employeeName: acc.name, ts, date: dateStr(ts), time: timeStr(ts), deviceId: DEVICE_ID,
    };
    await save('sales', ret);
    for (const it of sale.items) { const p = findProd(it.productId); if (p) { p.stockBase = (p.stockBase || 0) + it.qtyBase; await save('products', p); } }
    toast('تم إنشاء قائمة الاسترجاع وإعادة المخزون', 'b');
    closeTab(tab.id);
  }
}

/* ───────────────────────── 18) تقرير المشتريات ───────────────────────── */
function renderPurchaseReport(tab) {
  const st = tab.state;
    st.f = st.f || { supplier: '', employee: '', from: dateStr(), to: dateStr(), type: '', sortKey: 'ts', sortDir: 1 }; // يفتح على اليوم مباشرة
  const page = h('div', { class: 'page' });
  page.append(h('div', { class: 'page-head' }, h('div', { class: 'page-title' }, h('span', { html: icon('history') }), 'تقرير المشتريات')));
  const supSel = h('select', {}, h('option', { value: '' }, 'الكل'), state.suppliers.filter(s => !s.deleted).map(s => h('option', { value: s.id, selected: st.f.supplier === s.id }, s.name)));
  supSel.addEventListener('change', () => { st.f.supplier = supSel.value; draw(); });
  const empSel = h('select', {}, h('option', { value: '' }, 'الكل'), state.accounts.filter(a => !a.deleted).map(a => h('option', { value: a.id, selected: st.f.employee === a.id }, a.name)));
  empSel.addEventListener('change', () => { st.f.employee = empSel.value; draw(); });
  const fromI = h('input', { type: 'date', value: st.f.from }), toI = h('input', { type: 'date', value: st.f.to });
  fromI.addEventListener('change', () => { st.f.from = fromI.value; draw(); });
  toI.addEventListener('change', () => { st.f.to = toI.value; draw(); });
  const typeSel = h('select', {}, h('option', { value: '' }, 'الكل'), h('option', { value: 'purchase' }, 'شراء'), h('option', { value: 'return' }, 'استرجاع شراء'));
  typeSel.value = st.f.type;
  typeSel.addEventListener('change', () => { st.f.type = typeSel.value; draw(); });
  page.append(h('div', { class: 'filter-bar' },
    h('div', { class: 'f-group' }, h('label', {}, 'المذخر'), supSel),
    h('div', { class: 'f-group' }, h('label', {}, 'الموظف'), empSel),
    h('div', { class: 'f-group' }, h('label', {}, 'من'), fromI, h('label', {}, 'إلى'), toI),
    h('div', { class: 'f-group' }, h('label', {}, 'نوع العملية'), typeSel)));
  const bodyBox = h('div', { class: 'page-body' });
  const footBox = h('div', { class: 'page-footer' });
  page.append(bodyBox, footBox);
  const COLS = [['type','نوع العملية'],['employeeName','الموظف'],['supplierName','المذخر'],['date','التاريخ'],['time','الوقت'],['total','مبلغ القائمة'],['pay','نوع الدفع'],['debtAfter','الدين المتراكم'],[null,'تعديل']];
  function filtered() {
    return state.purchases.filter(p =>
      (!st.f.supplier || p.supplierId === st.f.supplier) && (!st.f.employee || p.employeeId === st.f.employee) &&
      (!st.f.from || p.date >= st.f.from) && (!st.f.to || p.date <= st.f.to) && (!st.f.type || p.type === st.f.type)
    ).sort((a, b) => {
      const k = st.f.sortKey; let va = a[k], vb = b[k];
      if (typeof va === 'string') return va.localeCompare(vb, 'ar') * st.f.sortDir;
      return ((va || 0) - (vb || 0)) * st.f.sortDir;
    });
  }
  function draw() {
    const rows = filtered();
    bodyBox.innerHTML = '';
    const thead = h('tr', {}, COLS.map(([k, label]) =>
      h('th', { class: k ? 'sortable' : '', onclick: k ? () => { if (st.f.sortKey === k) st.f.sortDir *= -1; else { st.f.sortKey = k; st.f.sortDir = -1; } draw(); } : null },
        label, st.f.sortKey === k ? h('span', { class: 'sort-arw' }, st.f.sortDir === -1 ? ' ▼' : ' ▲') : null)));
    const tbody = h('tbody');
    rows.forEach(p => tbody.append(h('tr', {},
      h('td', {}, h('span', { class: 'badge ' + (p.type === 'purchase' ? 'b' : 'r') }, p.type === 'purchase' ? 'شراء' : 'استرجاع'),
        p.version > 1 ? h('span', { class: 'badge n' }, `ع${p.version}`) : null),
      h('td', {}, p.employeeName), h('td', {}, p.supplierName),
      h('td', { class: 'mono' }, fmtDate(p.ts)), h('td', { class: 'mono' }, fmtTime(p.ts)),
      h('td', { class: 'td-num td-total' }, fmt(p.total)),
      h('td', {}, h('span', { class: 'badge ' + (p.pay === 'cash' ? 'g' : 'r') }, p.pay === 'cash' ? 'كاش' : 'آجل')),
      h('td', { class: 'td-num', style: { color: 'var(--red)', fontWeight: 900 } }, p.pay === 'credit' ? fmt(p.debtAfter) : '—'),
      h('td', {}, h('button', { class: 'icon-btn edit', html: icon('edit'), onclick: () => openTab('editpurch', { purchaseId: p.id }) })),
    )));
    bodyBox.append(h('div', { class: 'tbl-scroll' }, h('table', { class: 'tbl' }, h('thead', {}, thead), tbody)));
    if (!rows.length) bodyBox.append(h('div', { class: 'empty-note' }, 'لا نتائج ضمن الفلاتر المحددة'));
    /* الإجماليات */
    const tBuy = rows.filter(r => r.type === 'purchase').reduce((x, r) => x + r.total, 0) - rows.filter(r => r.type === 'return').reduce((x, r) => x + r.total, 0);
    let sellVal = 0, costVal = 0;
    rows.forEach(r => r.items.forEach(it => {
      const p = findProd(it.productId);
      const sign = r.type === 'purchase' ? 1 : -1;
      costVal += sign * it.total;
      if (p) sellVal += sign * salePerUnit(p, it.unitIdx) * it.qty;
    }));
    footBox.innerHTML = '';
    footBox.append(
      h('div', { class: 'sum-card b' }, h('label', {}, 'مبلغ المشتريات الكلي'), h('b', {}, fmt(tBuy))),
      h('div', { class: 'sum-card n' }, h('label', {}, 'قيمة بيع أصناف هذه القوائم'), h('b', {}, fmt(sellVal))),
      h('div', { class: 'sum-card big' }, h('label', {}, 'الربح المتوقع من هذه المشتريات'), h('b', {}, `${fmt(sellVal - costVal)} ${cur()}`)));
  }
  draw();
  tab.el.append(page);
}

/* ───────────────────────── 19) تعديل قائمة شراء ───────────────────────── */
function renderEditPurchase(tab) {
  const pu = state.purchases.find(p => p.id === tab.props.purchaseId);
  if (!pu) { tab.el.append(h('div', { class: 'empty-note' }, 'القائمة غير موجودة')); return; }
  const readonly = tab.props.readonly;
  const st = tab.state;
  st.viewVer = st.viewVer || pu.version;
  const isLatest = !readonly && st.viewVer === pu.version;
  const snap = isLatest || readonly && st.viewVer === pu.version ? pu : pu.versions[st.viewVer - 1];
  if (!st.editItems || st.savedFor !== pu.version) { st.editItems = JSON.parse(JSON.stringify(snap.items)); st.discount = snap.discount; st.pay = snap.pay; st.savedFor = null; }
  const page = h('div', { class: 'page' });
  page.append(h('div', { class: 'page-head' },
    h('div', { class: 'page-title' }, h('span', { html: icon(readonly ? 'eye' : 'edit') }), `${readonly ? 'عرض' : 'تعديل'} قائمة شراء رقم ${pu.listNum} — ${pu.supplierName}`),
    h('div', { class: 'spacer' }),
    h('div', { class: 'ver-pills' }, h('span', { class: 'ver-note' }, 'النسخة:'),
      ...Array.from({ length: pu.version }, (_, i) => i + 1).map(v =>
        h('button', { class: 'ver-pill' + (v === st.viewVer ? ' cur' : ''), onclick: () => { st.viewVer = v; st.savedFor = null; renderTabContent(tab); } }, v)))));
  if (!isLatest && !readonly)
    page.append(h('div', { class: 'readonly-banner' }, h('span', { html: icon('lock') }), `نسخة رقم ${st.viewVer} — قراءة فقط. التعديل على آخر نسخة فقط.`));
  const tbody = h('tbody');
  function drawItems() {
    tbody.innerHTML = '';
    st.editItems.forEach((it, i) => {
      const p = findProd(it.productId);
      tbody.append(h('tr', {},
        h('td', { class: 'td-seq' }, i + 1), h('td', { class: 'td-name' }, it.name),
        h('td', {}, it.unitName || (p ? p.units[it.unitIdx].name : '')),
        h('td', {}, isLatest ? (() => {
          const q = h('input', { type: 'number', value: it.qty, min: 1, style: { width: '70px', border: '1px solid var(--line)', borderRadius: '8px', padding: '5px', textAlign: 'center', fontWeight: 900 } });
          q.addEventListener('change', () => { it.qty = Math.max(1, num(q.value) || 1); drawT(); });
          return q;
        })() : fmt(it.qty)),
        h('td', {}, isLatest ? (() => {
          const pr = h('input', { type: 'number', value: it.buyPrice, min: 0, style: { width: '90px', border: '1px solid var(--line)', borderRadius: '8px', padding: '5px', textAlign: 'center', fontWeight: 900 } });
          pr.addEventListener('change', () => { it.buyPrice = num(pr.value); drawT(); });
          return pr;
        })() : fmt(it.buyPrice)),
        h('td', { class: 'td-num td-total' }, fmt(it.buyPrice * it.qty)),
        isLatest ? h('td', {}, h('button', { class: 'icon-btn del', html: icon('trash'), onclick: () => { st.editItems.splice(i, 1); drawItems(); drawT(); } })) : h('td', {}, ''),
      ));
    });
  }
  const netEl = h('b', {}, '0');
  function drawT() { netEl.textContent = `${fmt(Math.max(0, st.editItems.reduce((s, it) => s + it.buyPrice * it.qty, 0) - st.discount))} ${cur()}`; }
  const discInp = h('input', { type: 'number', value: st.discount, min: 0, disabled: !isLatest, style: { width: '100px', border: '1.5px solid var(--line)', borderRadius: '10px', padding: '7px', fontWeight: 900, textAlign: 'center' } });
  discInp.addEventListener('input', () => { st.discount = num(discInp.value); drawT(); });
  const paySel = h('select', { class: 'unit-select', disabled: !isLatest },
    h('option', { value: 'cash', selected: st.pay === 'cash' }, 'كاش'), h('option', { value: 'credit', selected: st.pay === 'credit' }, 'آجل'));
  paySel.addEventListener('change', () => st.pay = paySel.value);
  page.append(h('div', { class: 'cart-wrap', style: { flex: 'none', maxHeight: '52vh' } },
    h('div', { class: 'tbl-scroll' }, h('table', { class: 'tbl' },
      h('thead', {}, h('tr', {}, h('th', {}, 'ت'), h('th', {}, 'المنتج'), h('th', {}, 'الوحدة'), h('th', {}, 'العدد'), h('th', {}, 'سعر الشراء'), h('th', {}, 'المجموع'), h('th', {}, ''))), tbody))),
    h('div', { class: 'filter-bar' },
      h('div', { class: 'f-group' }, h('label', {}, 'الخصم'), discInp),
      h('div', { class: 'f-group' }, h('label', {}, 'نوع الدفع'), paySel),
      h('div', { class: 'spacer' }),
      h('div', { class: 'f-group' }, h('label', {}, 'الصافي'), netEl)));
  if (isLatest) {
    page.append(h('div', { style: { display: 'flex', gap: '10px' } },
      h('button', { class: 'btn g big', onclick: saveEdit }, h('span', { html: icon('check') }), 'حفظ التعديل (نسخة جديدة)'),
      pu.type === 'purchase' ? h('button', { class: 'btn r', onclick: makeReturn }, h('span', { html: icon('refresh') }), 'استرجاع للمذخر') : null));
  }
  tab.el.append(page);
  drawItems(); drawT();
  async function saveEdit() {
    if (!st.editItems.length) return toast('لا يمكن حفظ قائمة فارغة', 'r');
    pu.versions.push({ items: JSON.parse(JSON.stringify(pu.items)), total: pu.total, discount: pu.discount, pay: pu.pay });
    for (const it of pu.items) { const p = findProd(it.productId); if (p) p.stockBase = (p.stockBase || 0) - it.qtyBase; } // إرجاع أثر القديم
    const items = st.editItems.map(it => {
      const p = findProd(it.productId);
      return { ...it, qtyBase: p ? it.qty * unitFactor(p, it.unitIdx) : it.qty, total: it.buyPrice * it.qty };
    });
    for (const it of items) { const p = findProd(it.productId); if (p) { p.stockBase = (p.stockBase || 0) + it.qtyBase; await save('products', p); } }
    pu.items = items;
    pu.discount = st.discount;
    pu.total = Math.max(0, items.reduce((s, it) => s + it.total, 0) - st.discount);
    pu.pay = st.pay;
    pu.version += 1;
    pu.editedBy = me().name; pu.editedAt = Date.now();
    await save('purchases', pu);
    await recomputeSupplierDebt(pu.supplierId);
    st.savedFor = pu.version;
    toast(`حُفظت النسخة ${pu.version} وأُعيد حساب الدين المتراكم`);
    closeTab(tab.id);
  }
  async function makeReturn() {
    const yes = await confirmBox('سيتم إنشاء استرجاع شراء (إنقاص المخزون وتعديل دين المذخر). متابعة؟', { danger: true, okLabel: 'استرجاع', icon: 'refresh' });
    if (!yes) return;
    const ts = Date.now(); const acc = me();
    const ret = { id: uid(), type: 'return', version: 1, versions: [], originalId: pu.id,
      supplierId: pu.supplierId, supplierName: pu.supplierName, listNum: pu.listNum,
      items: JSON.parse(JSON.stringify(pu.items)), discount: pu.discount, total: pu.total, pay: pu.pay,
      employeeId: acc.id, employeeName: acc.name, ts, date: dateStr(ts), time: timeStr(ts), deviceId: DEVICE_ID };
    await save('purchases', ret);
    for (const it of pu.items) { const p = findProd(it.productId); if (p) { p.stockBase = (p.stockBase || 0) - it.qtyBase; await save('products', p); } }
    await recomputeSupplierDebt(pu.supplierId);
    toast('تم إنشاء استرجاع الشراء', 'b');
    closeTab(tab.id);
  }
}
/* إعادة حساب الدين المتراكم لمذخر — تطابق حسابي كامل بعد أي تعديل */
async function recomputeSupplierDebt(supplierId) {
  const sup = findSup(supplierId);
  if (!sup) return;
  const events = [
    ...state.purchases.filter(p => p.supplierId === supplierId && !p.deleted).map(p => ({ ts: p.ts, kind: 'p', doc: p })),
    ...state.payments.filter(p => p.supplierId === supplierId && !p.deleted).map(p => ({ ts: p.ts, kind: 'pay', doc: p })),
  ].sort((a, b) => a.ts - b.ts);
    let debt = sup.openingDebt || 0; // يبدأ التراكم من الرصيد الافتتاحي
  for (const ev of events) {
    if (ev.kind === 'p') {
      if (ev.doc.pay === 'credit') debt += ev.doc.type === 'purchase' ? ev.doc.total : -ev.doc.total;
      ev.doc.debtAfter = debt;
      await save('purchases', ev.doc);
    } else {
      debt -= ev.doc.amount + (ev.doc.kind === 'payment' ? (ev.doc.discount || 0) : 0); // التسديد والإيداع كلاهما يُنقص الدين
      ev.doc.debtAfter = debt;
      await save('payments', ev.doc);
    }
  }
  sup.debt = debt;
  const ps = state.purchases.filter(p => p.supplierId === supplierId && p.type === 'purchase' && !p.deleted).sort((a, b) => b.ts - a.ts);
  sup.lastPurchase = ps[0] ? { amount: ps[0].total, ts: ps[0].ts } : null;
  const pays = state.payments.filter(p => p.supplierId === supplierId && p.kind === 'payment' && !p.deleted).sort((a, b) => b.ts - a.ts);
  sup.lastPayment = pays[0] ? { amount: pays[0].amount, ts: pays[0].ts } : null;
  await save('suppliers', sup);
}

/* ───────────────────────── 20) المخزن ───────────────────────── */
function renderInventory(tab) {
  const st = tab.state;
  st.f = st.f || { q: '', sortKey: 'createdAt', sortDir: -1 };
  const page = h('div', { class: 'page' });
  page.append(h('div', { class: 'page-head' },
    h('div', { class: 'page-title' }, h('span', { html: icon('store') }), 'المخزن'),
    h('div', { class: 'spacer' }),
    h('button', { class: 'btn g', onclick: () => openTab('product') }, h('span', { html: icon('plus') }), 'إضافة صنف')));
  const qInp = h('input', { type: 'text', placeholder: 'بحث سريع بالاسم أو الباركود…', value: st.f.q });
  qInp.addEventListener('input', () => { st.f.q = qInp.value; draw(); });
  page.append(h('div', { class: 'filter-bar' }, h('div', { class: 'f-group', style: { flex: 1 } }, h('span', { html: icon('search') }), qInp)));
  const bodyBox = h('div', { class: 'page-body' });
  const footBox = h('div', { class: 'page-footer' });
  page.append(bodyBox, footBox);
  const COLS = [[null,'ت'],['brandName','اسم المنتج'],[null,'سعر الشراء'],[null,'سعر البيع'],[null,'ربح القطعة'],['stockBase','العدد (وحدة صغرى)'],['expiry','الإكسباير'],[null,'إجراء']];
  function draw() {
    let rows = state.products.filter(p => !p.deleted);
    if (st.f.q.trim()) { const q = st.f.q.trim().toLowerCase(); rows = rows.filter(p => p.brandName.toLowerCase().includes(q) || (p.barcodes || []).some(b => b.includes(q))); }
    rows.sort((a, b) => {
      const k = st.f.sortKey;
      if (k === 'brandName') return a.brandName.localeCompare(b.brandName, 'ar') * st.f.sortDir;
      return ((a[k] || 0) - (b[k] || 0)) * st.f.sortDir;
    });
    bodyBox.innerHTML = '';
    const tbody = h('tbody');
    rows.forEach((p, i) => {
      const cBase = p.purchasePriceTop / (baseFactor(p) || 1);
      const expired = p.expiry && p.expiry < dateStr().slice(0, 7);
      const nearExp = !expired && p.expiry && p.expiry <= dateStr(Date.now() + 90 * 864e5).slice(0, 7);
      tbody.append(h('tr', {},
        h('td', { class: 'td-seq' }, i + 1),
        h('td', { class: 'td-name' }, p.brandName,coTag(p), h('small', {}, `${p.scientificName || ''} ${p.form || ''} ${p.dose || ''}`.trim())),
        h('td', { class: 'td-num td-cost' }, fmt(cBase)),
        h('td', { class: 'td-num td-sale' }, fmt(p.salePriceBase)),
        h('td', { class: 'td-num', style: { color: 'var(--green)' } }, fmt(p.salePriceBase - cBase)),
        h('td', {}, h('span', { class: 'badge ' + ((p.stockBase || 0) <= 0 ? 'r' : (p.stockBase || 0) <= (state.settings.lowStock ?? 10) ? 'amber' : 'g') },
          `${fmt(p.stockBase || 0)} ${smallUnitName(p)}`)),
        h('td', {}, p.expiry ? h('span', { class: 'badge ' + (expired ? 'r' : nearExp ? 'amber' : 'n') }, p.expiry) : '—'),
        h('td', {}, h('div', { class: 'row-act' },
          h('button', { class: 'icon-btn view', title: 'تفاصيل وحركة المادة', html: icon('eye'), onclick: () => openTab('details', { productId: p.id }) }),
          h('button', { class: 'icon-btn edit', title: 'تعديل', html: icon('edit'), onclick: () => openTab('product', { productId: p.id }) }),
          h('button', { class: 'icon-btn del', title: 'حذف', html: icon('trash'), onclick: async () => {
            const yes = await confirmBox(`حذف «${p.brandName}» من المخزن؟ (تبقى حركاته السابقة محفوظة)`, { danger: true, okLabel: 'حذف' });
            if (yes) { p.deleted = true; await save('products', p); draw(); renderSideNav(); toast('تم الحذف', 'b'); }
          } }))),
      ));
    });
    bodyBox.append(h('div', { class: 'tbl-scroll' }, h('table', { class: 'tbl' },
      h('thead', {}, h('tr', {}, COLS.map(([k, label]) =>
        h('th', { class: k ? 'sortable' : '', onclick: k ? () => { if (st.f.sortKey === k) st.f.sortDir *= -1; else { st.f.sortKey = k; st.f.sortDir = 1; } draw(); } : null },
          label, st.f.sortKey === k ? h('span', { class: 'sort-arw' }, st.f.sortDir === -1 ? ' ▼' : ' ▲') : null)))),
      tbody)));
    if (!rows.length) bodyBox.append(h('div', { class: 'empty-note' }, 'المخزن فارغ — أضف الأصناف من قائمة الشراء'));
    let tCost = 0, tSale = 0;
    state.products.filter(p => !p.deleted).forEach(p => {
      const cBase = p.purchasePriceTop / (baseFactor(p) || 1);
      tCost += cBase * (p.stockBase || 0);
      tSale += p.salePriceBase * (p.stockBase || 0);
    });
    footBox.innerHTML = '';
    footBox.append(
      h('div', { class: 'sum-card b' }, h('label', {}, 'مجموع شراء المخزن'), h('b', {}, `${fmt(tCost)} ${cur()}`)),
      h('div', { class: 'sum-card n' }, h('label', {}, 'مجموع بيع المخزن'), h('b', {}, `${fmt(tSale)} ${cur()}`)),
      h('div', { class: 'sum-card big' }, h('label', {}, 'الربح المتوقع'), h('b', {}, `${fmt(tSale - tCost)} ${cur()}`)));
  }
  draw();
  tab.el.append(page);
}

/* ───────────────────────── 21) تفاصيل الصنف + حركة المادة ───────────────────────── */
function renderProductDetails(tab) {
  const p = findProd(tab.props.productId);
  if (!p) { tab.el.append(h('div', { class: 'empty-note' }, 'الصنف غير موجود')); return; }
  const st = tab.state;
    st.f = st.f || { from: dateStr(Date.now() - 30 * 864e5), to: dateStr() }; // الافتراضي: آخر 30 يوماً
  const cBase = p.purchasePriceTop / (baseFactor(p) || 1);
  const page = h('div', { class: 'page', style: { overflowY: 'auto' } });
  page.append(h('div', { class: 'page-head' },
    h('div', { class: 'page-title' }, h('span', { html: icon('pill') }), p.brandName , coTag(p)),
    p.featured ? h('span', { class: 'badge g' }, 'مميز') : null,
    h('div', { class: 'spacer' }),
    h('button', { class: 'btn b', onclick: () => openTab('product', { productId: p.id }) }, h('span', { html: icon('edit') }), 'تعديل الصنف')));
  page.append(h('div', { class: 'stat-cards' },
    h('div', { class: 'sum-card n' }, h('label', {}, 'الاسم العلمي'), h('b', { style: { fontSize: '15px' } }, p.scientificName || '—')),
    h('div', { class: 'sum-card n' }, h('label', {}, 'الشكل / الجرعة'), h('b', { style: { fontSize: '15px' } }, `${p.form || '—'} ${p.dose || ''}`)),
    h('div', { class: 'sum-card b' }, h('label', {}, 'شراء الوحدة الصغرى'), h('b', {}, fmt(cBase))),
    h('div', { class: 'sum-card g' }, h('label', {}, 'بيع الوحدة الصغرى'), h('b', {}, fmt(p.salePriceBase))),
    h('div', { class: 'sum-card ' + ((p.stockBase || 0) <= (state.settings.lowStock ?? 10) ? 'r' : 'g') }, h('label', {}, 'المخزون الحالي'), h('b', {}, `${fmt(p.stockBase || 0)} ${smallUnitName(p)}`)),
    h('div', { class: 'sum-card n' }, h('label', {}, 'الإكسباير'), h('b', {}, p.expiry || '—'))));
  page.append(h('div', { class: 'stat-cards' },
    h('div', { class: 'sum-card n' }, h('label', {}, 'الباركودات'),
      h('div', { class: 'barcode-list', style: { marginTop: '6px' } }, (p.barcodes || []).map(b => h('span', { class: 'barcode-chip' }, b)))),
    h('div', { class: 'sum-card n', style: { flex: 2 } }, h('label', {}, 'التعبئة والأرصدة لكل وحدة'),
      h('div', { class: 'price-preview', style: { marginTop: '6px' } }, p.units.map((u, i) =>
        h('span', { class: 'price-chip' }, `${u.name} ×${unitFactor(p, i)}`, h('b', {}, `${fmt(stockInUnit(p, i))} متوفر`)))))));

  /* حركة المادة */
  const fromI = h('input', { type: 'date', value: st.f.from }), toI = h('input', { type: 'date', value: st.f.to });
  fromI.addEventListener('change', () => { st.f.from = fromI.value; drawMov(); });
  toI.addEventListener('change', () => { st.f.to = toI.value; drawMov(); });
  const movBox = h('div', { class: 'page-body', style: { flex: 'none', maxHeight: '46vh' } });
    page.append(h('div', { class: 'filter-bar', style: { marginTop: '4px' } },
    h('span', { html: icon('history'), style: { color: 'var(--green)', display: 'flex' } }),
    h('label', { style: { fontWeight: 900 } }, 'حركة المادة'),
    h('div', { class: 'f-group' }, h('label', {}, 'من'), fromI, h('label', {}, 'إلى'), toI),
    h('button', { class: 'btn n', style: { padding: '7px 14px', fontSize: '12.5px' }, onclick: () => { st.f.from = ''; st.f.to = ''; fromI.value = ''; toI.value = ''; drawMov(); } }, 'منذ بداية النظام')));
  
    function drawMov() {
    const movs = [];
    state.sales.forEach(s => (s.items || []).forEach(it => {
      if (it.productId !== p.id) return;
      if (st.f.from && s.date < st.f.from || st.f.to && s.date > st.f.to) return;
      movs.push({ ts: s.ts, kind: s.type === 'sale' ? 'بيع' : 'استرجاع بيع', emp: s.employeeName,
        qty: s.type === 'sale' ? -it.qty : it.qty, qtyBase: s.type === 'sale' ? -it.qtyBase : it.qtyBase,
        price: it.sale, docType: 'sale', docId: s.id });
    }));
        state.purchases.forEach(pu => (pu.items || []).forEach(it => {
      if (pu.deleted || it.productId !== p.id) return;
      if (st.f.from && pu.date < st.f.from || st.f.to && pu.date > st.f.to) return;
      movs.push({ ts: pu.ts, kind: pu.type === 'purchase' ? 'شراء' : 'استرجاع شراء', emp: pu.employeeName,
        qty: pu.type === 'purchase' ? it.qty : -it.qty, qtyBase: pu.type === 'purchase' ? it.qtyBase : -it.qtyBase,
        price: it.buyPrice, docType: 'purchase', docId: pu.id });
    }));
    movs.sort((a, b) => a.ts - b.ts);
    const initial = (p.stockBase || 0) - movs.reduce((s, m) => s + m.qtyBase, 0);
    let cum = initial;
    movBox.innerHTML = '';
    const tbody = h('tbody');
    movs.forEach(m => {
      cum += m.qtyBase;
      tbody.append(h('tr', {},
        h('td', {}, h('span', { class: 'badge ' + (m.kind === 'بيع' ? 'g' : m.kind === 'شراء' ? 'b' : 'r') }, m.kind)),
        h('td', {}, m.emp), h('td', { class: 'mono' }, fmtDate(m.ts)), h('td', { class: 'mono' }, fmtTime(m.ts)),
        h('td', { class: 'td-num', style: { color: m.qty >= 0 ? 'var(--green)' : 'var(--red)' } }, (m.qty >= 0 ? '+' : '') + fmt(m.qty)),
        h('td', { class: 'td-num', style: { fontWeight: 900 } }, fmt(cum)),
        h('td', { class: 'td-num td-sale' }, fmt(m.price)),
        h('td', {}, h('button', { class: 'icon-btn edit', html: icon('edit'), title: 'فتح القائمة للتعديل',
          onclick: () => openTab(m.docType === 'sale' ? 'editsale' : 'editpurch', m.docType === 'sale' ? { saleId: m.docId } : { purchaseId: m.docId }) }))));
    });
    movBox.append(h('div', { class: 'tbl-scroll' }, h('table', { class: 'tbl' },
      h('thead', {}, h('tr', {}, h('th', {}, 'نوع العملية'), h('th', {}, 'الموظف'), h('th', {}, 'التاريخ'), h('th', {}, 'الوقت'),
        h('th', {}, `العدد (${smallUnitName(p)})`), h('th', {}, 'العدد التراكمي'), h('th', {}, 'سعر البيع / الشراء'), h('th', {}, 'تعديل'))), tbody)));
    if (!movs.length) movBox.append(h('div', { class: 'empty-note' }, 'لا حركات لهذا الصنف في الفترة المحددة'));
  }
  drawMov();
  tab.el.append(page);
}

/* إضافة مذخر مع رصيد افتتاحي (دين سابق قبل النظام) — موحّدة لكل الأزرار */
function openAddSupplierModal(onDone) {
  const nameInp = h('input', { placeholder: 'اسم المذخر / الشركة' });
  const debtInp = h('input', { type: 'number', min: 0, placeholder: '0' });
  openModal({
    title: 'إضافة مذخر جديد', icon: 'suppliers',
    body: h('div', { class: 'form-grid' },
      h('div', { class: 'f-field full' }, h('label', {}, 'اسم المذخر ', h('span', { class: 'req' }, '*')), nameInp),
      h('div', { class: 'f-field full' }, h('label', {}, 'الرصيد الافتتاحي — دين سابق علينا (اختياري)'), debtInp,
        h('div', { class: 'f-hint' }, 'إن كان للمذخر دين قديم قبل النظام فأدخله هنا؛ يظهر في كشف الحساب كرصيد افتتاحي ويُحسب ضمن الدين المتراكم'))),
    actions: [
      { label: 'إلغاء', cls: 'n', onClick: c => c() },
      { label: 'إضافة', cls: 'g', icon: 'check', big: true, onClick: async c => {
        const name = nameInp.value.trim();
        if (!name) return toast('أدخل اسم المذخر', 'r');
        const opening = num(debtInp.value);
        const s = { id: uid(), name, debt: opening, openingDebt: opening, createdAt: Date.now() };
        await save('suppliers', s);
        c();
        toast(`تمت إضافة المذخر «${name}»${opening ? ` برصيد افتتاحي ${fmt(opening)} ${cur()}` : ''}`);
        if (onDone) onDone(s);
      } },
    ],
  });
  nameInp.focus();
}

/* ───────────────────────── 22) حسابات المجهزين ───────────────────────── */
function renderSuppliers(tab) {
  const page = h('div', { class: 'page' });
  page.append(h('div', { class: 'page-head' },
    h('div', { class: 'page-title' }, h('span', { html: icon('suppliers') }), 'حسابات مجهزين'),
    h('div', { class: 'spacer' }),
        h('button', { class: 'btn g', onclick: () => openAddSupplierModal(() => renderTabContent(tab)) }, h('span', { html: icon('plus') }), 'إضافة مذخر')));
  const bodyBox = h('div', { class: 'page-body' });
  const tbody = h('tbody');
  state.suppliers.filter(s => !s.deleted).forEach(s => tbody.append(h('tr', {},
    h('td', { class: 'td-name' }, s.name),
    h('td', { class: 'td-num', style: { color: (s.debt || 0) > 0 ? 'var(--red)' : 'var(--green)', fontWeight: 900, fontSize: '15px' } }, `${fmt(s.debt || 0)} ${cur()}`),
    h('td', { class: 'td-num' }, s.lastPurchase ? fmt(s.lastPurchase.amount) : '—'),
    h('td', { class: 'mono' }, s.lastPurchase ? fmtDate(s.lastPurchase.ts) : '—'),
    h('td', { class: 'td-num', style: { color: 'var(--green)' } }, s.lastPayment ? fmt(s.lastPayment.amount) : '—'),
    h('td', { class: 'mono' }, s.lastPayment ? fmtDate(s.lastPayment.ts) : '—'),
    h('td', {}, h('div', { class: 'row-act' },
      h('button', { class: 'btn g', style: { padding: '8px 16px', fontSize: '13px' }, onclick: () => openPaymentModal(s.id) }, h('span', { html: icon('cash') }), 'تسديد'),
      h('button', { class: 'icon-btn del', title: 'حذف المذخر', html: icon('trash'), onclick: async () => {
        const yes = await confirmBox(`حذف المذخر «${s.name}»؟ (تبقى قوائمه محفوظة)`, { danger: true, okLabel: 'حذف' });
        if (yes) { s.deleted = true; await save('suppliers', s); renderTabContent(tab); }
      } }))),
  )));
  bodyBox.append(h('div', { class: 'tbl-scroll' }, h('table', { class: 'tbl' },
    h('thead', {}, h('tr', {}, h('th', {}, 'اسم المذخر'), h('th', {}, 'الدين المتراكم'), h('th', {}, 'آخر عملية شراء'), h('th', {}, 'تاريخها'), h('th', {}, 'آخر تسديد'), h('th', {}, 'تاريخه'), h('th', {}, 'إجراء'))), tbody)));
  if (!state.suppliers.filter(s => !s.deleted).length) bodyBox.append(h('div', { class: 'empty-note' }, 'لا مذخرين بعد — أضفهم من الزر أعلاه أو من قائمة الشراء'));
  page.append(bodyBox);
  tab.el.append(page);
}
function openPaymentModal(supplierId) {
  let kind = 'payment'; // payment = تسديد (ينزل الدين) | deposit = إيداع (يرفع الرصيد لصالحنا)
  const supSel = h('select', { style: { width: '100%', border: '1.5px solid var(--line)', borderRadius: '12px', padding: '11px 14px', fontWeight: 800, outline: 'none' } },
    state.suppliers.filter(s => !s.deleted).map(s => h('option', { value: s.id, selected: s.id === supplierId }, s.name)));
  const debtEl = h('b', { style: { fontSize: '26px', color: 'var(--red)' } }, '0');
  const afterEl = h('b', { style: { fontSize: '17px' } }, '0');
  const amtInp = h('input', { type: 'number', min: 0, placeholder: '0' });
  const discAmt = h('input', { type: 'number', min: 0, placeholder: '0' });
  const discPct = h('input', { type: 'number', min: 0, placeholder: '0', style: { width: '80px' } });
  function current() { return (findSup(supSel.value) || { debt: 0 }).debt || 0; }
  function recalc(fromPct) {
    const amt = num(amtInp.value);
    if (fromPct) discAmt.value = Math.round(amt * num(discPct.value) / 100);
    else discPct.value = amt ? Math.round(num(discAmt.value) / amt * 1000) / 10 : 0;
    const total = amt + num(discAmt.value);
    const after = kind === 'payment' ? current() - total : current() - amt;
    afterEl.textContent = `${fmt(after)} ${cur()}`;
    afterEl.style.color = after > 0 ? 'var(--red)' : 'var(--green)';
    debtEl.textContent = `${fmt(current())} ${cur()}`;
  }
  supSel.addEventListener('change', () => recalc());
  amtInp.addEventListener('input', () => recalc(true));
  discPct.addEventListener('input', () => recalc(true));
  discAmt.addEventListener('input', () => recalc(false));
  const kindBtns = h('div', { class: 'pay-row' },
    h('button', { class: 'pay-btn cash', style: { height: '46px', fontSize: '14px' }, onclick: function () { kind = 'payment'; selKind(this); recalc(); } }, 'تسديد (تخفيض الدين)'),
    h('button', { class: 'pay-btn electronic', style: { height: '46px', fontSize: '14px', opacity: .55 }, onclick: function () { kind = 'deposit'; selKind(this); recalc(); } }, 'إيداع (دفعة مقدمة)'));
  function selKind(btn) { $$('.pay-btn', kindBtns).forEach(b => b.style.opacity = .55); btn.style.opacity = 1; }
  openModal({
    title: 'تسديد المذخر', icon: 'cash', wide: true,
    body: h('div', { class: 'form-grid' },
      h('div', { class: 'f-field full' }, h('label', {}, 'المذخر'), supSel),
      h('div', { class: 'f-field full' }, h('div', { class: 'sum-card r', style: { textAlign: 'center' } }, h('label', {}, 'الدين المتراكم الحالي'), debtEl)),
      h('div', { class: 'f-field full' }, kindBtns),
      h('div', { class: 'f-field' }, h('label', {}, 'المبلغ المسدد ', h('span', { class: 'req' }, '*')), amtInp),
      h('div', { class: 'f-field' }, h('label', {}, 'الخصم الحاصل'), h('div', { class: 'input-group' }, discAmt, discPct, h('span', { style: { alignSelf: 'center', fontWeight: 900 } }, '%'))),
      h('div', { class: 'f-field full' }, h('div', { class: 'sum-card n', style: { textAlign: 'center' } }, h('label', {}, 'الدين بعد العملية'), afterEl))),
    actions: [
      { label: 'إلغاء', cls: 'n', onClick: c => c() },
      { label: 'تنفيذ وحفظ', cls: 'g', icon: 'check', big: true, onClick: async c => {
        const amt = num(amtInp.value);
        if (!amt) return toast('أدخل المبلغ المسدد', 'r');
        const sup = findSup(supSel.value);
        const ts = Date.now(); const acc = me();
        const payDoc = { id: uid(), supplierId: sup.id, supplierName: sup.name, amount: amt, discount: num(discAmt.value),
          kind, employeeId: acc.id, employeeName: acc.name, ts, date: dateStr(ts), time: timeStr(ts) };
        sup.debt = kind === 'payment' ? (sup.debt || 0) - (amt + payDoc.discount) : (sup.debt || 0) - amt;
        payDoc.debtAfter = sup.debt;
        if (kind === 'payment') sup.lastPayment = { amount: amt, ts };
        await save('payments', payDoc);
        await save('suppliers', sup);
        c(); refreshActiveTab();
        toast(`تمت العملية — الدين الحالي: ${fmt(sup.debt)} ${cur()}`);
      } },
    ],
  });
  recalc();
  amtInp.focus();
}

/* ───────────────────────── 23) الإعدادات ───────────────────────── */
function renderSettings(tab) {
  const st = tab.state;
  st.section = st.section || 'profile';
  const acc = me();
  const page = h('div', { class: 'page', style: { overflowY: 'auto' } });
  page.append(h('div', { class: 'page-head' }, h('div', { class: 'page-title' }, h('span', { html: icon('settings') }), 'الإعدادات')));
  const SECTIONS = [['profile','حسابي'],['pharmacy','الصيدلية والنظام'],['accounts','إدارة الحسابات'],['scanner','الماسح الذكي'],['backup','النسخ الاحتياطي']];
    const nav = h('div', { class: 'settings-nav' }, SECTIONS // الصلاحيات مفتوحة: كل الحسابات ترى كل الأقسام حالياً (بطلبك)
    .map(([k, l]) => h('div', { class: 'set-chip' + (st.section === k ? ' active' : ''), onclick: () => { st.section = k; renderTabContent(tab); } }, l)));
  page.append(nav);
  const box = h('div', { class: 'page-body', style: { padding: '20px', overflowY: 'auto' } });
  page.append(box);

  if (st.section === 'profile') {
    const nameInp = h('input', { value: acc.name });
        const passInp = h('input', { type: 'password', placeholder: 'اتركه فارغاً لإبقاء الحالية', autocomplete: 'new-password', dir: 'ltr' });
    const fileInp = h('input', { type: 'file', accept: 'image/*' });
    let photo = acc.photo;
        const apInner = h('div', { class: 'ap-inner' }, avatarNode(acc));
        fileInp.addEventListener('change', () => readAvatarFile(fileInp, data => {
      photo = data; apInner.innerHTML = ''; apInner.append(avatarNode({ photo, gender: acc.gender }));
    }));
    box.append(h('div', { class: 'form-grid', style: { maxWidth: '560px' } },
      h('div', { class: 'f-field full' }, h('div', { class: 'avatar-preview' },
        h('div', { class: 'ap-frame' }, apInner, h('label', { class: 'ap-edit', html: icon('camera') }, fileInp)))),
      h('div', { class: 'f-field' }, h('label', {}, 'اسم الحساب'), nameInp),
      h('div', { class: 'f-field' }, h('label', {}, 'كلمة المرور'), passInp),
      h('div', { class: 'f-field full' },
                h('button', { class: 'btn g', onclick: async () => {
          const n = nameInp.value.trim(), pw = passInp.value;
          if (!n) return toast('أدخل اسم الحساب', 'r');
          acc.name = n; acc.photo = photo;
          if (pw.trim()) await setPassword(acc, pw); // فارغ = لا تغيير على كلمة المرور
          await save('accounts', acc);
          renderTopbar(); toast('تم حفظ بيانات حسابك');
        } }, h('span', { html: icon('check') }), 'حفظ التعديلات'))));
   }     
  else if (st.section === 'pharmacy') {
    const phInp = h('input', { value: state.settings.pharmacyName });
    const pctInp = h('input', { type: 'number', min: 0, value: state.settings.profitPct ?? 30 });
    const lowInp = h('input', { type: 'number', min: 0, value: state.settings.lowStock ?? 10 });
    const curInp = h('input', { value: state.settings.currency || 'د.ع' });
    box.append(h('div', { class: 'form-grid', style: { maxWidth: '620px' } },
      h('div', { class: 'f-field' }, h('label', {}, 'اسم الصيدلية'), phInp),
      h('div', { class: 'f-field' }, h('label', {}, 'العملة'), curInp),
      h('div', { class: 'f-field' }, h('label', {}, 'نسبة الربح الافتراضية %'), pctInp, h('div', { class: 'f-hint' }, 'تُطبق تلقائياً عند إضافة صنف جديد')),
      h('div', { class: 'f-field' }, h('label', {}, 'حد النواقص (بالوحدة الصغرى)'), lowInp, h('div', { class: 'f-hint' }, 'تنبيه عند بلوغ المخزون هذا الحد')),
      h('div', { class: 'f-field full' },
        h('button', { class: 'btn g', onclick: async () => {
          state.settings.pharmacyName = phInp.value.trim() || 'صيدلية درب الشفاء';
          state.settings.profitPct = num(pctInp.value);
          state.settings.lowStock = num(lowInp.value);
          state.settings.currency = curInp.value.trim() || 'د.ع';
          await save('settings', state.settings);
          renderTopbar(); renderSideNav(); toast('تم حفظ إعدادات النظام');
        } }, h('span', { html: icon('check') }), 'حفظ الإعدادات'))));
  }
  else if (st.section === 'accounts') {
    const list = h('div', {});
    state.accounts.filter(a => !a.deleted).forEach(a => list.append(h('div', { class: 'inv-mini', style: { display: 'flex', alignItems: 'center', gap: '12px' } },
            accountAvatar(a, 38),
      h('div', { style: { flex: 1 } }, h('b', {}, a.name), ' ', a.role === 'admin' ? h('span', { class: 'badge b' }, 'مدير') : h('span', { class: 'badge n' }, 'موظف')),
      h('button', { class: 'mini-btn blue', style: { flex: 'none' }, onclick: async () => {
                const pw = await promptBox(`كلمة مرور جديدة لـ «${a.name}» — أي طول مسموح`, { type: 'password' });
        if (pw) { await setPassword(a, pw); await save('accounts', a); toast('تم تغيير كلمة المرور'); }
      } }, 'تغيير كلمة المرور'),
      a.role !== 'admin' ? h('button', { class: 'mini-btn ' + (a.role === 'admin' ? 'n' : 'green'), style: { flex: 'none' }, onclick: async () => {
        a.role = a.role === 'admin' ? 'staff' : 'admin';
        await save('accounts', a); renderTabContent(tab);
      } }, a.role === 'admin' ? 'إلغاء الإدارة' : 'جعله مديراً') : null,
      a.id !== acc.id ? h('button', { class: 'mini-btn red', style: { flex: 'none' }, onclick: async () => {
        const yes = await confirmBox(`حذف حساب «${a.name}» نهائياً؟`, { danger: true, okLabel: 'حذف' });
        if (yes) { a.deleted = true; await save('accounts', a); renderTabContent(tab); toast('تم حذف الحساب', 'b'); }
      } }, 'حذف') : h('span', { class: 'badge g' }, 'أنت'))));
    box.append(h('h4', { style: { fontWeight: 900, marginBottom: '12px' } }, 'الحسابات المسجلة'), list);
  }
  else if (st.section === 'scanner') {
    const keyInp = h('input', { type: 'password', value: state.settings.geminiKey || '', placeholder: 'AIza...' });
    box.append(h('div', { class: 'form-grid', style: { maxWidth: '560px' } },
      h('div', { class: 'f-field full' }, h('label', {}, 'مفتاح Gemini API (مجاني من Google AI Studio)'), keyInp,
        h('div', { class: 'f-hint' }, 'احصل عليه من aistudio.google.com ثم الصقه هنا. يُستخدم لقراءة الفواتير الورقية بالصور.')),
      h('div', { class: 'f-field full' }, h('button', { class: 'btn g', onclick: async () => {
        state.settings.geminiKey = keyInp.value.trim();
        await save('settings', state.settings);
        toast('تم حفظ المفتاح');
      } }, h('span', { html: icon('check') }), 'حفظ المفتاح')),
      h('div', { class: 'f-field full' }, h('button', { class: 'btn b', onclick: () => openTab('scanner') }, h('span', { html: icon('camera') }), 'فتح الماسح الذكي'))));
  }
  else if (st.section === 'backup') {
    const fileInp = h('input', { type: 'file', accept: '.json', style: { display: 'none' } });
    fileInp.addEventListener('change', () => {
      const f = fileInp.files[0]; if (!f) return;
      const r = new FileReader();
      r.onload = async () => {
        try {
          const data = JSON.parse(r.result);
          for (const k of ['accounts','products','sales','purchases','suppliers','payments','customers']) if (data[k]) await DB.bulk(k, data[k]);
          if (data.settings) await DB.put('settings', data.settings);
          toast('تمت الاستعادة — سيُعاد تشغيل النظام', 'b');
          setTimeout(() => location.reload(), 1200);
        } catch (e) { toast('ملف غير صالح', 'r'); }
      };
      r.readAsText(f);
    });
    box.append(h('div', { class: 'form-grid', style: { maxWidth: '560px' } },
      h('div', { class: 'f-field full' }, h('div', { class: 'sum-card g', style: { textAlign: 'center' } },
        h('label', {}, 'إحصائيات البيانات'),
        h('b', { style: { fontSize: '15px' } }, `${state.products.filter(p=>!p.deleted).length} صنف • ${state.sales.length} قائمة بيع • ${state.purchases.length} قائمة شراء • ${state.suppliers.filter(s=>!s.deleted).length} مذخر`))),
      h('div', { class: 'f-field full' }, h('button', { class: 'btn b big', onclick: async () => {
        const data = {};
        for (const k of ['accounts','products','sales','purchases','suppliers','payments','customers']) data[k] = await DB.all(k);
        data.settings = state.settings;
        const blob = new Blob([JSON.stringify(data)], { type: 'application/json' });
        const a = h('a', { href: URL.createObjectURL(blob), download: `نسخة-احتياطية-درب-الشفاء-${dateStr()}.json` });
        a.click();
        toast('تم تصدير النسخة الاحتياطية');
      } }, h('span', { html: icon('download') }), 'تصدير نسخة احتياطية كاملة')),
      h('div', { class: 'f-field full' }, h('button', { class: 'btn n big', onclick: () => fileInp.click() }, h('span', { html: icon('upload') }), 'استعادة من نسخة احتياطية'), fileInp),
      Sync.ready ? h('div', { class: 'f-field full' }, h('button', { class: 'btn g big', onclick: async () => { await Sync.uploadAll(); toast('تم رفع كل البيانات المحلية إلى Firebase'); } }, h('span', { html: icon('upload') }), 'رفع كل البيانات المحلية إلى السحابة')) : null));
  }
  tab.el.append(page);
}

/* ───────────────────────── 24) تبويب الماسح الذكي ───────────────────────── */
function renderScannerTab(tab) {
  const page = h('div', { class: 'page', style: { overflowY: 'auto' } });
  page.append(h('div', { class: 'page-head' }, h('div', { class: 'page-title' }, h('span', { html: icon('camera') }), 'قراءة الفواتير الورقية بالصور')));
  const mount = h('div', { class: 'page-body', style: { padding: '18px', overflowY: 'auto' } });
  page.append(mount);
  tab.el.append(page);
  InvoiceScanner.mount(mount, {
    getKey: () => state.settings.geminiKey,
    onImport: items => {
      const rt = tab.props.returnTab && tabs.find(t => t.id === tab.props.returnTab);
      if (rt && rt.type === 'purchase') {
        items.forEach(it => {
          const p = state.products.find(x => !x.deleted && x.brandName.toLowerCase() === (it.name || '').toLowerCase());
          if (p) addPurchaseItem(rt, p, it.qty || 1);
        });
        activateTab(rt.id);
      } else {
        const nt = openTab('purchase');
        items.forEach(it => {
          const p = state.products.find(x => !x.deleted && x.brandName.toLowerCase() === (it.name || '').toLowerCase());
          if (p) addPurchaseItem(nt, p, it.qty || 1);
        });
      }
      toast(`استُوردت ${items.length} مادة من الفاتورة`);
    },
    onNewProduct: (name, qty, price) => openTab('product', { title: 'إضافة صنف', state: { prefill: { name, qty, price } } }),
  });
}

/* ───────────────────────── 24-أ) إرجاع بيع (واجهة نقطة البيع + لوح ذكي) ───────────────────────── */
function renderReturnSale(tab) {
  const st = tab.state;
  st.cart = st.cart || [];
  st.discount = st.discount || 0;
  const wrap = h('div', { class: 'pos-layout' });
  const center = h('div', { class: 'pos-center' });

  /* محرك البحث */
  const sInput = h('input', { placeholder: 'ابحث عن الصنف المُرجَع أو امسح باركوده…', autocomplete: 'off' });
  const sugBox = h('div', { class: 'suggestions' });
  st.searchInput = sInput;
  sInput.addEventListener('input', () => {
    const q = sInput.value;
    const sugItems = searchProducts(q);
    sugBox.innerHTML = '';
    if (!q.trim()) { sugBox.classList.remove('show'); return; }
    if (!sugItems.length) sugBox.append(h('div', { class: 'sug-empty' }, `لا نتائج لـ «${q}»`));
    else sugItems.forEach(p => sugBox.append(h('div', { class: 'sug-item', onclick: () => pick(p) },
      h('span', { class: 'sug-ic', html: icon('pill') }),
      h('div', { class: 'sug-name' }, p.brandName, coTag(p),h('small', {}, `${p.scientificName || ''}${p.scientificName ? ' • ' : ''}${p.form || ''} ${p.dose || ''}`)),
      h('span', { class: 'sug-price' }, `${fmt(salePerUnit(p, p.units.length - 1))} ${cur()}`))));
    sugBox.classList.add('show');
  });
  sInput.addEventListener('keydown', e => {
    if (e.key === 'Enter') {
      const sugItems = searchProducts(sInput.value);
      if (sugItems.length) pick(sugItems[0]);
      else if (sInput.value.trim()) toast('لا يوجد صنف مطابق', 'r');
    } else if (e.key === 'Escape') sugBox.classList.remove('show');
  });
  document.addEventListener('mousedown', e => { if (!sugBox.contains(e.target) && e.target !== sInput) sugBox.classList.remove('show'); });
  function pick(p) { addRetItem(tab, p); sInput.value = ''; sugBox.classList.remove('show'); sInput.focus(); }
  center.append(h('div', { class: 'search-engine' },
    h('div', { class: 'search-box' }, h('span', { html: icon('search') }), sInput,
      h('span', { class: 'search-hint' }, 'المُرجَع يعود للمخزون تلقائياً')), sugBox));

  /* سلة الإرجاع */
  const cartWrap = h('div', { class: 'cart-wrap' });
  st.renderCart = () => {
    cartWrap.innerHTML = '';
    if (!st.cart.length) {
      cartWrap.append(h('div', { class: 'cart-empty' }, h('span', { html: icon('refresh') }),
        h('p', {}, 'سلة الإرجاع فارغة — أدخل الأصناف المُرجعة من الزبون')));
      return;
    }
    const tbody = h('tbody');
    st.cart.forEach((it, i) => {
      const p = findProd(it.productId);
      tbody.append(h('tr', { class: it.productId === st.activeProductId ? 'row-focus' : '' },
        h('td', { class: 'td-seq' }, i + 1),
        h('td', { class: 'td-name', style: { cursor: 'pointer' }, title: 'اضغط لعرض سجل بيع هذا الصنف في اللوح الجانبي',
          onclick: () => { st.activeProductId = it.productId; st.renderCart(); st.drawSide(); } },
          it.name,coTag(p), h('small', {}, p ? `${p.form || ''} ${p.dose || ''}` : '')),
        h('td', {}, (() => {
          const sel = h('select', { class: 'unit-select' }, (p ? p.units : [{ name: it.unitName }]).map((u, ui) => h('option', { value: ui, selected: ui === it.unitIdx }, u.name)));
          sel.addEventListener('change', () => {
            it.unitIdx = +sel.value;
            if (p) { it.sale = salePerUnit(p, it.unitIdx); it.cost = costPerUnit(p, it.unitIdx); }
            st.renderCart(); st.renderTotals();
          });
          return sel;
        })()),
        h('td', {}, (() => {
          const q = h('input', { type: 'number', value: it.qty, min: 0.5, step: 'any' });
          q.addEventListener('change', () => { it.qty = Math.max(0.5, num(q.value) || 1); st.renderCart(); st.renderTotals(); });
          return h('div', { class: 'qty-ctl' },
            h('button', { onclick: () => { it.qty++; st.renderCart(); st.renderTotals(); } }, '+'), q,
            h('button', { onclick: () => { if (it.qty > 1) { it.qty--; st.renderCart(); st.renderTotals(); } } }, '−'));
        })()),
        h('td', { class: 'td-num td-sale' }, fmt(it.sale)),
        h('td', { class: 'td-num td-total' }, fmt(it.sale * it.qty)),
        h('td', {}, h('div', { class: 'row-act' },
          h('button', { class: 'icon-btn view', title: 'تفاصيل المنتج', html: icon('eye'), onclick: () => openTab('details', { productId: it.productId }) }),
          h('button', { class: 'icon-btn del', title: 'حذف من السلة', html: icon('trash'), onclick: () => { st.cart.splice(i, 1); st.renderCart(); st.renderTotals(); } }))),
      ));
    });
    cartWrap.append(h('div', { class: 'tbl-scroll' },
      h('table', { class: 'tbl' },
        h('thead', {}, h('tr', {}, h('th', {}, 'ت'), h('th', {}, 'اسم المنتج'), h('th', {}, 'الوحدة'), h('th', {}, 'العدد'),
          h('th', {}, 'سعر البيع'), h('th', {}, 'المجموع'), h('th', {}, 'إجراء'))),
        tbody)));
  };

  /* الإجماليات + زر الإرجاع الوحيد */
  const subEl = h('div', { class: 'tval' }, '0');
  const grandEl = h('div', { class: 'tval' }, h('span', {}, '0'), ' ', h('small', {}, cur()));
  const discInp = h('input', { type: 'number', min: 0, placeholder: '0', value: st.discount || '' });
  discInp.addEventListener('input', () => { st.discount = num(discInp.value); st.renderTotals(); });
  st.renderTotals = () => {
    const sub = st.cart.reduce((s, it) => s + it.sale * it.qty, 0);
    subEl.textContent = fmt(sub);
    grandEl.firstChild.textContent = fmt(Math.max(0, sub - st.discount));
  };
  const footer = h('div', { class: 'pos-footer' },
    h('div', { class: 'totals-row' },
      h('div', { class: 'total-card' }, h('label', {}, 'مجموع المسترجع'), subEl),
      h('div', { class: 'total-card' }, h('label', {}, 'الخصم'), h('div', { class: 'discount-wrap' }, discInp)),
      h('div', { class: 'total-card grand red-grand' }, h('label', {}, 'المبلغ المسترجع للزبون'), grandEl)),
    h('div', { class: 'pay-row' },
      h('button', { class: 'pay-btn credit', onclick: () => finalizeReturnSale(tab) },
        h('span', { html: icon('refresh') }), 'إرجاع البيع')));

  /* اللوح الذكي (25%): آخر 5 فواتير بيع لآخر صنف أُدخل — ويتبدل تلقائياً مع كل صنف جديد */
  const side = h('div', { class: 'pos-side' });
  side.append(h('div', { class: 'side-tabs' }, h('div', { class: 'side-tab active' }, 'سجل بيع الصنف')));
  const sideBody = h('div', { class: 'side-body' });
  st.drawSide = () => {
    sideBody.innerHTML = '';
    const pid = st.activeProductId;
    if (!pid) { sideBody.append(h('div', { class: 'empty-note' }, 'أدخل أي صنف لسلة الإرجاع', h('br'), 'وستظهر هنا آخر 5 قوائم بيع له')); return; }
    const p = findProd(pid);
    sideBody.append(h('div', { class: 'inv-mini', style: { cursor: 'default', borderColor: 'var(--green-soft)', background: 'var(--green-ghost)' } },
      h('div', { class: 'im-top' }, h('span', {}, p ? p.brandName : '—'), h('span', { class: 'badge g' }, 'آخر 5 مبيعات'))));
    const sales = state.sales.filter(s => s.type === 'sale' && (s.items || []).some(x => x.productId === pid)).sort((a, b) => b.ts - a.ts).slice(0, 5);
    if (!sales.length) { sideBody.append(h('div', { class: 'empty-note' }, 'لم يُبع هذا الصنف سابقاً')); return; }
    sales.forEach(s => {
      const itm = s.items.find(x => x.productId === pid);
      sideBody.append(h('div', { class: 'inv-mini', style: { cursor: 'default' } },
        h('div', { class: 'im-top' }, h('span', {}, `${fmtDate(s.ts)} • ${fmtTime(s.ts)}`), h('b', {}, `${fmt(itm.qty)} ${itm.unitName || ''}`)),
        h('div', { class: 'im-sub' }, h('span', {}, `${s.employeeName} • ${s.customerName || 'زبون نقدي'}`), h('span', { class: 'badge g' }, `${fmt(itm.total)} ${cur()}`)),
        h('div', { class: 'side-actions', style: { margin: '8px 0 0' } },
          h('button', { class: 'mini-btn blue', onclick: () => viewSaleModal(s) }, h('span', { html: icon('eye') }), 'عرض'),
                    h('button', { class: 'mini-btn green', onclick: () => openTab('editsale', { saleId: s.id }) }, h('span', { html: icon('edit') }), 'تعديل'))));
    });
  };
  side.append(sideBody);

  center.append(cartWrap);
  wrap.append(h('div', { style: { flex: 1, display: 'flex', minHeight: 0 } }, center, side), footer);
  tab.el.append(wrap);
  st.renderCart(); st.renderTotals(); st.drawSide();
  setTimeout(() => sInput.focus(), 60);
}
function addRetItem(tab, p) {
  const st = tab.state;
  const ex = st.cart.find(it => it.productId === p.id && it.unitIdx === p.units.length - 1);
  if (ex) ex.qty++;
  else st.cart.push({ productId: p.id, name: p.brandName, unitIdx: p.units.length - 1, qty: 1,
    cost: costPerUnit(p, p.units.length - 1), sale: salePerUnit(p, p.units.length - 1) });
  st.activeProductId = p.id; // اللوح الذكي يتبع آخر صنف مُدخل
  st.renderCart(); st.renderTotals(); st.drawSide();
}
async function finalizeReturnSale(tab) {
  const st = tab.state;
  if (st.processing) return;
  if (!st.cart.length) return toast('سلة الإرجاع فارغة', 'r');
  const yes = await confirmBox('تأكيد إرجاع البيع؟ ستعود الأصناف إلى المخزون وتُسجَّل العملية في تقرير المبيعات كاسترجاع بيع.', { okLabel: 'إرجاع البيع', icon: 'refresh', danger: true });
  if (!yes) return;
  st.processing = true;
  const acc = me();
  const items = st.cart.map(it => {
    const p = findProd(it.productId);
    return { ...it, unitName: p ? p.units[it.unitIdx].name : it.unitName || '', qtyBase: p ? it.qty * unitFactor(p, it.unitIdx) : it.qty, total: it.sale * it.qty };
  });
  const subtotal = items.reduce((s, it) => s + it.total, 0);
  const cost = items.reduce((s, it) => s + it.cost * it.qty, 0);
  const net = Math.max(0, subtotal - st.discount);
  const ts = Date.now();
  const ret = {
    id: uid(), type: 'return', version: 1, versions: [],
    items, subtotal, discount: st.discount, net, cost, profit: -(net - cost),
    pay: 'cash', customerId: state.customerId, customerName: state.customerId ? (findCust(state.customerId) || {}).name : 'زبون نقدي',
    employeeId: acc.id, employeeName: acc.name,
    ts, date: dateStr(ts), time: timeStr(ts), deviceId: DEVICE_ID,
  };
  await save('sales', ret);
  for (const it of items) { const p = findProd(it.productId); if (p) { p.stockBase = (p.stockBase || 0) + it.qtyBase; await save('products', p); } }
  st.cart = []; st.discount = 0; st.activeProductId = null; st.processing = false;
  renderTabContent(tab); renderSideNav();
  toast(`تم إرجاع البيع — ${fmt(net)} ${cur()} وعادت الأصناف للمخزون`, 'b');
}

/* ───────────────────────── 24-ب) إرجاع شراء ───────────────────────── */
function renderReturnPurchase(tab) {
  const st = tab.state;
  st.items = st.items || [];
  const page = h('div', { class: 'pos-layout' });
  const center = h('div', { class: 'pos-center' });

  const supSel = h('select', {}, h('option', { value: '' }, '— اختر المذخر —'),
    state.suppliers.filter(s => !s.deleted).map(s => h('option', { value: s.id, selected: st.supplierId === s.id }, s.name)));
  const debtEl = h('b', { style: { color: 'var(--red)', fontSize: '15px' } }, '—');
  const drawDebt = () => { const s = findSup(st.supplierId); debtEl.textContent = s ? `${fmt(s.debt || 0)} ${cur()}` : '—'; };
  supSel.addEventListener('change', () => { st.supplierId = supSel.value || null; drawDebt(); });
  drawDebt();
  center.append(h('div', { class: 'filter-bar' },
    h('div', { class: 'f-group' }, h('label', {}, 'المذخر'), supSel),
    h('div', { class: 'f-group' }, h('label', {}, 'الدين الحالي'), debtEl),
    h('div', { class: 'spacer' })));

  const sInput = h('input', { placeholder: 'أدخل باركود الصنف المُرجَع أو ابحث بالاسم…', autocomplete: 'off' });
  const sugBox = h('div', { class: 'suggestions' });
  sInput.addEventListener('input', () => {
    const q = sInput.value;
    const sugItems = searchProducts(q);
    sugBox.innerHTML = '';
    if (!q.trim()) { sugBox.classList.remove('show'); return; }
    if (!sugItems.length) sugBox.append(h('div', { class: 'sug-empty' }, 'غير موجود في المخزن'));
    else sugItems.forEach(p => sugBox.append(h('div', { class: 'sug-item', onclick: () => pick(p) },
      h('span', { class: 'sug-ic', html: icon('pill') }),
      h('div', { class: 'sug-name' }, p.brandName,coTag(p), h('small', {}, `${p.form || ''} ${p.dose || ''}`)),
      h('span', { class: 'sug-price' }, `شراء ${fmt(costPerUnit(p, 0))} / ${bigUnitName(p)}`))));
    sugBox.classList.add('show');
  });
  sInput.addEventListener('keydown', e => {
    if (e.key !== 'Enter') return;
    const sugItems = searchProducts(sInput.value);
    if (sugItems.length) pick(sugItems[0]);
  });
  function pick(p) { addRetPurchItem(tab, p); sInput.value = ''; sugBox.classList.remove('show'); sInput.focus(); }
  center.append(h('div', { class: 'search-engine' },
    h('div', { class: 'search-box' }, h('span', { html: icon('barcode') }), sInput,
      h('span', { class: 'search-hint' }, 'الإرجاع يُنقص المخزون')), sugBox));

  const cartWrap = h('div', { class: 'cart-wrap' });
  st.renderItems = () => {
    cartWrap.innerHTML = '';
    if (!st.items.length) {
      cartWrap.append(h('div', { class: 'cart-empty' }, h('span', { html: icon('purchase') }), h('p', {}, 'أدخل الأصناف المُرجعة للمذخر')));
      return;
    }
    const tbody = h('tbody');
    st.items.forEach((it, i) => {
      const p = findProd(it.productId);
      tbody.append(h('tr', {},
        h('td', { class: 'td-seq' }, i + 1),
        h('td', { class: 'td-name' }, it.name, h('small', {}, p ? `${p.form || ''} ${p.dose || ''}` : '')),
        h('td', {}, p ? (() => {
          const sel = h('select', { class: 'unit-select' }, p.units.map((u, ui) => h('option', { value: ui, selected: ui === it.unitIdx }, u.name)));
          sel.addEventListener('change', () => { it.unitIdx = +sel.value; it.buyPrice = Math.round(costPerUnit(p, it.unitIdx) * 100) / 100; st.renderItems(); drawTotals(); });
          return sel;
        })() : (it.unitName || '')),
        h('td', {}, (() => {
          const q = h('input', { type: 'number', value: it.qty, min: 1, style: { width: '70px', border: '1px solid var(--line)', borderRadius: '8px', padding: '5px', textAlign: 'center', fontWeight: 900 } });
          q.addEventListener('change', () => { it.qty = Math.max(1, num(q.value) || 1); drawTotals(); });
          return q;
        })()),
        h('td', {}, (() => {
          const pr = h('input', { type: 'number', value: it.buyPrice, min: 0, style: { width: '90px', border: '1px solid var(--line)', borderRadius: '8px', padding: '5px', textAlign: 'center', fontWeight: 900 } });
          pr.addEventListener('change', () => { it.buyPrice = num(pr.value); drawTotals(); });
          return pr;
        })()),
        h('td', { class: 'td-num td-total' }, fmt(it.buyPrice * it.qty)),
        h('td', {}, h('button', { class: 'icon-btn del', html: icon('trash'), onclick: () => { st.items.splice(i, 1); st.renderItems(); drawTotals(); } })),
      ));
    });
    cartWrap.append(h('div', { class: 'tbl-scroll' },
      h('table', { class: 'tbl' },
        h('thead', {}, h('tr', {}, h('th', {}, 'ت'), h('th', {}, 'المنتج'), h('th', {}, 'الوحدة'), h('th', {}, 'العدد'), h('th', {}, 'سعر الشراء'), h('th', {}, 'المجموع'), h('th', {}, 'حذف'))),
        tbody)));
  };

  const totalEl = h('div', { class: 'tval' }, h('span', {}, '0'), ' ', h('small', {}, cur()));
  function drawTotals() { totalEl.firstChild.textContent = fmt(st.items.reduce((s, it) => s + it.buyPrice * it.qty, 0)); }
  const footer = h('div', { class: 'pos-footer' },
    h('div', { class: 'totals-row' },
      h('div', { class: 'total-card grand red-grand' }, h('label', {}, 'إجمالي المُرجَع للمذخر'), totalEl)),
    h('div', { class: 'pay-row' },
      h('button', { class: 'pay-btn credit', onclick: () => saveReturnPurchaseModal(tab) }, h('span', { html: icon('refresh') }), 'حفظ إرجاع الشراء')));

  center.append(cartWrap);
  const side = h('div', { class: 'pos-side' });
  side.append(h('div', { class: 'side-tabs' }, h('div', { class: 'side-tab active' }, 'استرجاعات الشراء السابقة')));
  const sideBody = h('div', { class: 'side-body' });
    state.purchases.filter(p => p.type === 'purchase' && !p.deleted).sort((a, b) => b.ts - a.ts).slice(0, 30).forEach(pu =>
    sideBody.append(h('div', { class: 'inv-mini', onclick: () => openTab('editpurch', { purchaseId: pu.id, readonly: true }) },
      h('div', { class: 'im-top' }, h('span', {}, pu.supplierName), h('b', {}, `${fmt(pu.total)} ${cur()}`)),
      h('div', { class: 'im-sub' }, h('span', {}, `${fmtDate(pu.ts)} ${fmtTime(pu.ts)}`),
        h('span', { class: 'badge ' + (pu.pay === 'cash' ? 'g' : 'r') }, pu.pay === 'cash' ? 'كاش مسترد' : 'أُنقص من الدين')))));
  if (!sideBody.children.length) sideBody.append(h('div', { class: 'empty-note' }, 'لا استرجاعات سابقة'));
  side.append(sideBody);
  page.append(h('div', { style: { flex: 1, display: 'flex', minHeight: 0 } }, center, side), footer);
  tab.el.append(page);
  st.renderItems(); drawTotals();
  setTimeout(() => sInput.focus(), 60);
}
function addRetPurchItem(tab, p) {
  const st = tab.state;
  st.items = st.items || [];
  const ex = st.items.find(it => it.productId === p.id && it.unitIdx === 0);
  if (ex) ex.qty += 1;
  else st.items.push({ productId: p.id, name: p.brandName, unitIdx: 0, qty: 1, buyPrice: costPerUnit(p, 0) });
  if (st.renderItems) st.renderItems();
}
async function saveReturnPurchaseModal(tab) {
  const st = tab.state;
  if (!st.items.length) return toast('القائمة فارغة', 'r');
  if (!st.supplierId) return toast('اختر المذخر أولاً', 'r');
  const sup = findSup(st.supplierId);
  const total = st.items.reduce((s, it) => s + it.buyPrice * it.qty, 0);
  openModal({
    title: 'تسوية إرجاع الشراء', icon: 'refresh',
    body: h('div', {},
      h('div', { class: 'sum-card r', style: { marginBottom: '10px' } }, h('label', {}, `قيمة الأصناف المُرجعة للمذخر «${sup.name}»`), h('b', {}, `${fmt(total)} ${cur()}`)),
      h('div', { class: 'sum-card n' }, h('label', {}, 'الدين الحالي قبل الإرجاع'), h('b', {}, `${fmt(sup.debt || 0)} ${cur()}`))),
    actions: [
      { label: 'إلغاء', cls: 'n', onClick: c => c() },
      { label: 'آجل (يُنقص الدين)', cls: 'r', icon: 'clock', big: true, onClick: c => { c(); finalizeReturnPurchase(tab, 'credit'); } },
      { label: 'كاش (مبلغ مسترد)', cls: 'g', icon: 'cash', big: true, onClick: c => { c(); finalizeReturnPurchase(tab, 'cash'); } },
    ],
  });
}
async function finalizeReturnPurchase(tab, pay) {
  const st = tab.state;
  const sup = findSup(st.supplierId);
  const acc = me();
  const ts = Date.now();
  const items = st.items.map(it => {
    const p = findProd(it.productId);
    return { ...it, unitName: p ? p.units[it.unitIdx].name : '', qtyBase: p ? it.qty * unitFactor(p, it.unitIdx) : it.qty, total: it.buyPrice * it.qty };
  });
  const total = items.reduce((s, it) => s + it.total, 0);
  const pu = {
    id: uid(), type: 'return', version: 1, versions: [],
    supplierId: sup.id, supplierName: sup.name, listNum: state.purchases.length + 1,
    items, discount: 0, total, pay, debtAfter: sup.debt || 0,
    employeeId: acc.id, employeeName: acc.name,
    ts, date: dateStr(ts), time: timeStr(ts), deviceId: DEVICE_ID,
  };
  await save('purchases', pu);
  for (const it of items) { const p = findProd(it.productId); if (p) { p.stockBase = (p.stockBase || 0) - it.qtyBase; await save('products', p); } }
  await recomputeSupplierDebt(sup.id); // يُنقص الدين إذا كان الإرجاع آجلاً + يعيد حساب debtAfter لكل السجل
  st.items = []; st.supplierId = null;
  renderTabContent(tab); renderSideNav();
  toast(`حُفظ إرجاع الشراء — ${fmt(total)} ${cur()} ${pay === 'credit' ? '(أُنقص من دين المذخر)' : '(مبلغ مسترد نقداً)'}`, 'b');
}

/* ───────────────────────── 24-ج) كشف حساب مذخر ───────────────────────── */
function renderStatement(tab) {
  const st = tab.state;
  st.f = st.f || { supplier: '', from: '', to: '' };
  const page = h('div', { class: 'page' });
  page.append(h('div', { class: 'page-head' }, h('div', { class: 'page-title' }, h('span', { html: icon('receipt') }), 'كشف حساب مذخر')));
  const supSel = h('select', {}, h('option', { value: '' }, '— اختر المذخر —'),
    state.suppliers.filter(s => !s.deleted).map(s => h('option', { value: s.id, selected: st.f.supplier === s.id }, s.name)));
  supSel.addEventListener('change', () => { st.f.supplier = supSel.value; draw(); });
  const fromI = h('input', { type: 'date', value: st.f.from }), toI = h('input', { type: 'date', value: st.f.to });
  fromI.addEventListener('change', () => { st.f.from = fromI.value; draw(); });
  toI.addEventListener('change', () => { st.f.to = toI.value; draw(); });
  page.append(h('div', { class: 'filter-bar' },
    h('div', { class: 'f-group' }, h('label', {}, 'المذخر'), supSel),
    h('div', { class: 'f-group' }, h('label', {}, 'من'), fromI, h('label', {}, 'إلى'), toI)));
  const bodyBox = h('div', { class: 'page-body' });
  const footBox = h('div', { class: 'page-footer' });
  page.append(bodyBox, footBox);

    function allEvents() { /* كل حركات المذخر مرتبة تصاعدياً لحساب الرصيد المتراكم الصحيح */
    if (!st.f.supplier) return [];
    const evs = [];
    const sup0 = findSup(st.f.supplier);
    if (sup0 && sup0.openingDebt) evs.push({ kind: 'opening', ts: sup0.createdAt || 0,
      doc: { supplierName: sup0.name, amount: sup0.openingDebt, ts: sup0.createdAt || Date.now(), date: dateStr(sup0.createdAt || Date.now()), time: timeStr(sup0.createdAt || Date.now()) } });
    state.purchases.filter(p => p.supplierId === st.f.supplier && !p.deleted)
      .forEach(p => evs.push({ kind: p.type === 'purchase' ? 'buy' : 'buyret', doc: p, ts: p.ts }));
    state.payments.filter(p => p.supplierId === st.f.supplier && !p.deleted)
      .forEach(p => evs.push({ kind: p.kind === 'deposit' ? 'deposit' : 'pay', doc: p, ts: p.ts }));
    evs.sort((a, b) => a.ts - b.ts);
    let run = 0;
    evs.forEach(e => {
      const d = e.doc;
      if (e.kind === 'opening') run += d.amount;
      else if (e.kind === 'buy') run += d.pay === 'credit' ? d.total : 0;
      else if (e.kind === 'buyret') run -= d.pay === 'credit' ? d.total : 0;
      else if (e.kind === 'pay') run -= d.amount + (d.discount || 0);
      else run -= d.amount;
      e.after = run; // الرصيد المتراكم بعد العملية مباشرة
    });
    return evs;
  }
  function draw() {
    bodyBox.innerHTML = ''; footBox.innerHTML = '';
    if (!st.f.supplier) { bodyBox.append(h('div', { class: 'empty-note' }, 'اختر مذخراً من الأعلى لعرض كشف حسابه الكامل')); return; }
    const sup = findSup(st.f.supplier);
    const evs = allEvents().filter(e => {
      const d = e.doc;
      return (!st.f.from || d.date >= st.f.from) && (!st.f.to || d.date <= st.f.to);
    });
    const tbody = h('tbody');
    [...evs].reverse().forEach(e => { /* العرض: الأحدث أولاً */
      const d = e.doc;
            const isDoc = e.kind === 'buy' || e.kind === 'buyret';
      const label = e.kind === 'opening' ? 'رصيد افتتاحي' : e.kind === 'buy' ? 'شراء' : e.kind === 'buyret' ? 'استرجاع شراء' : e.kind === 'pay' ? 'تسديد' : 'إيداع';
      const badgeCls = e.kind === 'opening' ? 'n' : e.kind === 'buy' ? 'b' : e.kind === 'buyret' ? 'r' : e.kind === 'pay' ? 'g' : 'n';
      const amount = isDoc ? d.total : (e.kind === 'pay' ? d.amount + (d.discount || 0) : d.amount);
      const sign = (e.kind === 'buy' || e.kind === 'opening') ? '+' : '−';
      const edited = isDoc && (d.version || 1) > 1;
      tbody.append(h('tr', {},
        h('td', { class: 'td-name' }, d.supplierName || (sup ? sup.name : '—')),
        h('td', {}, h('span', { class: 'badge ' + badgeCls }, label),
          edited ? h('span', { class: 'badge n', title: 'عُدّلت — عدد التعديلات' }, `ع${d.version}`) : null),
        h('td', { class: 'mono' }, fmtDate(d.ts)),
        h('td', { class: 'mono' }, fmtTime(d.ts)),
        h('td', { class: 'td-num', style: { color: e.kind === 'buy' ? 'var(--red)' : 'var(--green)' } }, `${sign} ${fmt(amount)}`),
        h('td', { class: 'td-num', style: { fontWeight: 900, color: e.after > 0 ? 'var(--red)' : 'var(--green)' } }, fmt(e.after)),
                h('td', {}, e.kind === 'opening' ? '' : h('div', { class: 'row-act' },
          isDoc ? h('button', { class: 'icon-btn view', title: 'عرض القائمة', html: icon('eye'), onclick: () => openTab('editpurch', { purchaseId: d.id, readonly: true }) }) : null,
          isDoc
            ? h('button', { class: 'icon-btn edit', title: 'تعديل القائمة', html: icon('edit'), onclick: () => openTab('editpurch', { purchaseId: d.id }) })
            : h('button', { class: 'icon-btn edit', title: 'تعديل المبلغ', html: icon('edit'), onclick: () => editPaymentModal(d) }),
          h('button', { class: 'icon-btn del', title: 'حذف نهائي', html: icon('trash'), onclick: () => isDoc ? deletePurchaseDoc(d) : deletePaymentDoc(d) }))),
      ));
    });
    bodyBox.append(h('div', { class: 'tbl-scroll' }, h('table', { class: 'tbl' },
      h('thead', {}, h('tr', {}, h('th', {}, 'اسم المذخر'), h('th', {}, 'نوع العملية'), h('th', {}, 'التاريخ'), h('th', {}, 'وقت الحفظ'),
        h('th', {}, 'المبلغ'), h('th', {}, 'الرصيد المتراكم'), h('th', {}, 'إجراء'))), tbody)));
    if (!evs.length) bodyBox.append(h('div', { class: 'empty-note' }, 'لا عمليات لهذا المذخر في الفترة المحددة'));
    const buys = evs.filter(e => e.kind === 'buy').reduce((s, e) => s + e.doc.total, 0);
    const rets = evs.filter(e => e.kind === 'buyret').reduce((s, e) => s + e.doc.total, 0);
    const pays = evs.filter(e => e.kind === 'pay' || e.kind === 'deposit').reduce((s, e) => s + e.doc.amount + (e.doc.discount || 0), 0);
    footBox.append(
      h('div', { class: 'sum-card b' }, h('label', {}, 'إجمالي المشتريات'), h('b', {}, fmt(buys))),
      h('div', { class: 'sum-card r' }, h('label', {}, 'إجمالي الاسترجاعات'), h('b', {}, fmt(rets))),
      h('div', { class: 'sum-card g' }, h('label', {}, 'إجمالي التسديدات والإيداعات'), h('b', {}, fmt(pays))),
      h('div', { class: 'sum-card big' }, h('label', {}, 'الدين المتراكم الحالي'), h('b', {}, `${fmt(sup ? sup.debt || 0 : 0)} ${cur()}`)));
  }
  draw();
  tab.el.append(page);
}

/* عرض/تعديل/حذف عمليات كشف الحساب — الحذف يعكس أثره على المخزون والدين */
function editPaymentModal(pay) {
  const amtInp = h('input', { type: 'number', min: 0, value: pay.amount });
  const discInp = h('input', { type: 'number', min: 0, value: pay.discount || 0 });
  openModal({
    title: `تعديل ${pay.kind === 'deposit' ? 'إيداع' : 'تسديد'} — ${pay.supplierName || ''}`, icon: 'edit',
    body: h('div', { class: 'form-grid' },
      h('div', { class: 'f-field' }, h('label', {}, 'المبلغ'), amtInp),
      h('div', { class: 'f-field' }, h('label', {}, 'الخصم'), discInp)),
    actions: [
      { label: 'إلغاء', cls: 'n', onClick: c => c() },
      { label: 'حفظ التعديل', cls: 'g', icon: 'check', big: true, onClick: async c => {
        pay.amount = num(amtInp.value); pay.discount = num(discInp.value);
        await save('payments', pay);
        await recomputeSupplierDebt(pay.supplierId);
        c(); refreshActiveTab(); toast('حُفظ التعديل وأُعيد حساب الدين المتراكم');
      } },
    ],
  });
}
async function deletePurchaseDoc(pu) {
  const yes = await confirmBox(`حذف ${pu.type === 'purchase' ? 'قائمة الشراء' : 'استرجاع الشراء'} رقم ${pu.listNum} نهائياً؟ سيُعكس أثرها على المخزون ويُعاد حساب دين المذخر.`, { danger: true, okLabel: 'حذف نهائي' });
  if (!yes) return;
  for (const it of pu.items || []) {
    const p = findProd(it.productId);
    if (p) { p.stockBase = (p.stockBase || 0) + (pu.type === 'purchase' ? -it.qtyBase : it.qtyBase); await save('products', p); }
  }
  pu.deleted = true; // حذف منطقي — يُزامَن لكل الأجهزة عبر save→push، يُخفى من التقارير، ويبقى قابلاً للتدقيق
  await save('purchases', pu);
  await recomputeSupplierDebt(pu.supplierId);
  refreshActiveTab(); renderSideNav();
  toast('حُذفت القائمة وعُكس أثرها على المخزون والدين', 'b');
}
async function deletePaymentDoc(pay) {
  const yes = await confirmBox('حذف عملية التسديد/الإيداع نهائياً؟ سيُعاد حساب دين المذخر.', { danger: true, okLabel: 'حذف نهائي' });
  if (!yes) return;
  pay.deleted = true;
  await save('payments', pay);
  await recomputeSupplierDebt(pay.supplierId);
  refreshActiveTab();
  toast('حُذفت العملية وأُعيد حساب الدين', 'b');
}

/* ───────────────────────── 25) الإقلاع ───────────────────────── */
async function init() {
  $('#tab-add').innerHTML = icon('plus');
  $('#tab-add').onclick = () => openTab('pos');
  try {
    await DB.open();
    const [accounts, products, sales, purchases, suppliers, payments, customers, settingsArr] = await Promise.all(
      ['accounts','products','sales','purchases','suppliers','payments','customers','settings'].map(s => DB.all(s)));
    state.accounts = accounts; state.products = products; state.sales = sales; state.purchases = purchases;
    state.suppliers = suppliers; state.payments = payments; state.customers = customers;
    state.settings = settingsArr.find(s => s.id === 'app') || { ...DEFAULT_SETTINGS };
    if (!settingsArr.find(s => s.id === 'app')) await DB.put('settings', state.settings);
        /* ترحيل لمرة واحدة: أي كلمة مرور صريحة قديمة → بصمة PBKDF2. لا توجد كلمة مرور افتراضية في الكود إطلاقاً —
       تثبيت جديد بلا حسابات؟ زر «إنشاء حساب» بشاشة الدخول يصنع أول حساب ويمنحه دور المدير تلقائياً */
    for (const a of state.accounts) {
      if (a.password != null) {
        const wasDefault = a.id === 'acc_default_admin' && String(a.password) === '2005';
        await setPassword(a, a.password);
        if (wasDefault) a.mustChangePass = true; // كلمة 2005 المعروفة: إجبار على التغيير عند أول دخول
        await save('accounts', a);
      }
    }
  } catch (e) {
    console.error('init failed:', e);
    const row = $('#accounts-row'); row.innerHTML = '';
    row.append(h('div', { style: { textAlign: 'center', color: 'var(--red)', fontWeight: 800, lineHeight: 2.2 } },
      'تعذّر تحميل قاعدة البيانات المحلية', h('br'), String((e && e.message) || e), h('br'),
      h('button', { class: 'btn g', onclick: () => location.reload() }, 'إعادة المحاولة')));
    return;
  }
   renderLogin(); tickLoginClock();
  Sync.init();
  /* رفع تلقائي فوري بلا زر: عند عودة الاتصال أكمل التهيئة أو ارفع الطابور، وأعد المحاولة كل 30 ثانية */
  window.addEventListener('online', () => { if (Sync.ready) Sync.flush(); else Sync.init(); });
  setInterval(() => { if (Sync.ready) Sync.flush(); }, 30000);
}
document.addEventListener('DOMContentLoaded', init);
