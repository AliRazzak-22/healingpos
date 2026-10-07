/* ═══════════════════════════════════════════════════════════════
   الماسح الذكي — قراءة الفواتير الورقية بالصور (Gemini 1.5 Flash)
   يرفع الصورة → يستخرج (الاسم الإنجليزي، الكمية، السعر، المجموع)
   بصيغة JSON → جدول قابل للتعديل → استيراد لقائمة الشراء
   ═══════════════════════════════════════════════════════════════ */
window.InvoiceScanner = (() => {

  const PROMPT = `You are an expert pharmaceutical invoice OCR system.
Analyze this invoice image and extract EVERY line item.
Return ONLY a JSON array (no markdown, no explanation) where each item is:
{"name": "<drug brand name in English exactly as written>", "quantity": <number>, "unit_price": <number>, "total": <number>}
Rules:
- Drug names must be in English as printed on the invoice.
- quantity, unit_price, total must be plain numbers.
- If a value is unreadable, use 0.
- Ignore headers, totals rows, taxes, and any non-product lines.
- Output must start with [ and end with ] and nothing else.`;

  async function extract(imageBase64, mime, apiKey) {
    const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${apiKey}`;
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [{ text: PROMPT }, { inline_data: { mime_type: mime, data: imageBase64 } }] }],
        generationConfig: { temperature: 0.1, maxOutputTokens: 4096 },
      }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err?.error?.message || `HTTP ${res.status}`);
    }
    const data = await res.json();
    let text = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
    text = text.replace(/```json|```/g, '').trim();
    const start = text.indexOf('['), end = text.lastIndexOf(']');
    if (start < 0 || end < 0) throw new Error('تعذر استخراج بيانات من الصورة');
    const arr = JSON.parse(text.slice(start, end + 1));
    return arr.map(x => ({
      name: String(x.name || '').trim(),
      qty: +x.quantity || 0,
      price: +x.unit_price || 0,
      total: +x.total || 0,
    })).filter(x => x.name);
  }

  function mount(rootEl, { getKey, onImport }) {
    let items = [];
    rootEl.innerHTML = '';

    const fileInp = document.createElement('input');
    fileInp.type = 'file'; fileInp.accept = 'image/*'; fileInp.style.display = 'none';

    const drop = document.createElement('div');
    drop.className = 'scan-drop';
    drop.innerHTML = `
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="4"/></svg>
      <div style="font-weight:900;font-size:16px">ارفع صورة الفاتورة الورقية</div>
      <div style="font-weight:700;font-size:12.5px;margin-top:4px">اضغط للاختيار أو اسحب الصورة هنا — يدعم فواتير المذاخر العراقية</div>`;
    drop.onclick = () => fileInp.click();
    drop.ondragover = e => { e.preventDefault(); drop.classList.add('over'); };
    drop.ondragleave = () => drop.classList.remove('over');
    drop.ondrop = e => { e.preventDefault(); drop.classList.remove('over'); if (e.dataTransfer.files[0]) handle(e.dataTransfer.files[0]); };
    fileInp.onchange = () => { if (fileInp.files[0]) handle(fileInp.files[0]); };

    const stage = document.createElement('div');
    stage.style.marginTop = '16px';
    rootEl.append(drop, fileInp, stage);

    async function handle(file) {
      const key = getKey();
      if (!key) {
        stage.innerHTML = `<div class="readonly-banner" style="margin-top:4px"><b>مفتاح Gemini غير موجود</b> — أدخله من: الإعدادات ← الماسح الذكي</div>`;
        return;
      }
      const reader = new FileReader();
      reader.onload = async () => {
        const dataUrl = reader.result;
        const base64 = dataUrl.split(',')[1];
        stage.innerHTML = `
          <div style="display:flex;gap:18px;flex-wrap:wrap">
            <img class="scan-preview" src="${dataUrl}">
            <div style="flex:1;min-width:260px;display:flex;flex-direction:column;gap:12px;justify-content:center">
              <div class="spinner"></div>
              <div style="text-align:center;font-weight:800;color:var(--muted)">Gemini يقرأ الفاتورة الآن…<br>عادةً 3–8 ثوانٍ</div>
            </div>
          </div>`;
        try {
          items = await extract(base64, file.type || 'image/jpeg', key);
          if (!items.length) throw new Error('لم يُعثر على مواد في الفاتورة');
          drawTable(dataUrl);
        } catch (e) {
          stage.innerHTML = `<div class="readonly-banner" style="border-color:var(--red-soft);background:var(--red-ghost);color:var(--red)">
            <b>فشلت القراءة:</b> ${e.message || e}<br>جرّب صورة أوضح وبإضاءة جيدة.</div>`;
        }
      };
      reader.readAsDataURL(file);
    }

    function drawTable(imgUrl) {
      stage.innerHTML = '';
      const wrap = document.createElement('div');
      wrap.style.display = 'flex'; wrap.style.flexDirection = 'column'; wrap.style.gap = '14px';

      const head = document.createElement('div');
      head.style.cssText = 'display:flex;align-items:center;gap:12px;flex-wrap:wrap';
      head.innerHTML = `<span class="badge g">تم استخراج ${items.length} مادة</span>
        <span style="font-weight:700;color:var(--muted);font-size:12.5px">راجع الأسماء والكميات وعدّل أي خطأ قبل الاستيراد</span>`;

      const tbl = document.createElement('table');
      tbl.className = 'tbl editable-table';
      tbl.innerHTML = `<thead><tr><th>ت</th><th>اسم العلاج (إنجليزي)</th><th>الكمية</th><th>السعر المفرد</th><th>المجموع</th><th>الحالة</th><th></th></tr></thead>`;
      const tbody = document.createElement('tbody');

      function rowMatch(name) {
        const n = name.toLowerCase();
        return state.products.find(p => !p.deleted && p.brandName.toLowerCase() === n)
            || state.products.find(p => !p.deleted && (p.brandName.toLowerCase().includes(n) || n.includes(p.brandName.toLowerCase())));
      }

      items.forEach((it, i) => {
        const tr = document.createElement('tr');
        const match = rowMatch(it.name);
        tr.innerHTML = `
          <td class="td-seq">${i + 1}</td>
          <td><input data-f="name" value="${it.name.replace(/"/g, '&quot;')}"></td>
          <td style="width:100px"><input data-f="qty" type="number" value="${it.qty}"></td>
          <td style="width:120px"><input data-f="price" type="number" value="${it.price}"></td>
          <td class="td-num td-total">${(it.qty * it.price || it.total).toLocaleString('en-US')}</td>
          <td>${match
            ? `<span class="badge g">موجود: ${match.brandName}</span>`
            : `<span class="badge amber">جديد — سيُضاف عند الاستيراد</span>`}</td>
          <td><button class="icon-btn del" title="حذف السطر"><svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M3 6h18M8 6V4a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2m3 0v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/></svg></button></td>`;
        tr.querySelectorAll('input').forEach(inp => inp.addEventListener('input', () => {
          it[inp.dataset.f] = inp.dataset.f === 'name' ? inp.value : +inp.value || 0;
          tr.children[4].textContent = (it.qty * it.price || it.total).toLocaleString('en-US');
        }));
        tr.querySelector('.icon-btn').onclick = () => { items.splice(i, 1); drawTable(imgUrl); };
        tbody.append(tr);
      });
      tbl.append(tbody);

      const foot = document.createElement('div');
      foot.style.cssText = 'display:flex;gap:10px;align-items:center';
      const img = document.createElement('img');
      img.className = 'scan-preview'; img.src = imgUrl; img.style.maxHeight = '120px';
      const importBtn = document.createElement('button');
      importBtn.className = 'btn g big';
      importBtn.innerHTML = 'استيراد إلى قائمة الشراء';
      importBtn.onclick = async () => {
        // الأصناف غير الموجودة: أنشئها تلقائياً بالاسم والسعر، وتُكمل تفاصيلها لاحقاً
        for (const it of items) {
          if (!rowMatch(it.name)) {
            const p = {
              id: Math.random().toString(36).slice(2) + Date.now().toString(36),
              brandName: it.name, scientificName: '', barcodes: [], form: 'Tab', dose: '', expiry: '',
              featured: false, units: [{ name: 'علبة', perNext: 1 }],
              purchasePriceTop: it.price || 0,
              salePriceBase: Math.round((it.price || 0) * 1.3),
              stockBase: 0, createdAt: Date.now(), fromScanner: true,
            };
            await DB.put('products', p);
            state.products.push(p);
          }
        }
        onImport(items);
      };
      const newBtn = document.createElement('button');
      newBtn.className = 'btn n';
      newBtn.textContent = 'فاتورة أخرى';
      newBtn.onclick = () => { items = []; stage.innerHTML = ''; fileInp.value = ''; };
      foot.append(importBtn, newBtn, document.createElement('span'), img);
      foot.children[2].style.flex = 1;

      wrap.append(head, tbl, foot);
      stage.append(wrap);
    }
  }

  return { mount };
})();
