"use strict";
// susanoo の Web コンソール（2p）。設定の JSON を、入力欄と JSON の欄のどちらでも編集する。保存はサーバーの検証に通ったものだけ。
(() => {
  const $ = (id) => document.getElementById(id);
  const state = { obj: {}, hash: "", fields: [], kind: "", service: "", checked: null, formatted: "" };

  async function api(path, body) {
    const opt = body === undefined ? {} : { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
    const res = await fetch(path, opt);
    let data;
    try { data = await res.json(); } catch (e) { data = { ok: false, errors: ["応答を読めません（" + res.status + "）"] }; }
    return { status: res.status, data };
  }

  function getPath(obj, path) {
    return path.split(".").reduce((o, k) => (o !== null && typeof o === "object" && !Array.isArray(o) ? o[k] : undefined), obj);
  }

  // setPath は値を置く。undefined なら項目を消し、空になった入れ物も消す。
  function setPath(obj, path, value) {
    const keys = path.split(".");
    const parents = [];
    let o = obj;
    for (let i = 0; i < keys.length - 1; i++) {
      const k = keys[i];
      if (o[k] === null || typeof o[k] !== "object" || Array.isArray(o[k])) {
        if (value === undefined) return;
        o[k] = {};
      }
      parents.push([o, k]);
      o = o[k];
    }
    const last = keys[keys.length - 1];
    if (value === undefined) delete o[last]; else o[last] = value;
    for (let i = parents.length - 1; i >= 0; i--) {
      const [p, k] = parents[i];
      if (Object.keys(p[k]).length !== 0) break;
      delete p[k];
    }
  }

  const splitList = (s) => s.split(",").map((v) => v.trim()).filter((v) => v !== "");

  function shown(f, v) {
    if (v === undefined || v === null) return "";
    switch (f.type) {
      case "bool": return v === true ? "true" : v === false ? "false" : "";
      case "list": case "numbers": return Array.isArray(v) ? v.join(", ") : JSON.stringify(v);
      case "objlist": return Array.isArray(v) ? v.map((e) => (e && e[f.key]) || "").filter((s) => s).join(", ") : "";
      default: return typeof v === "object" ? JSON.stringify(v) : String(v);
    }
  }

  // parse は入力欄の文字を設定の値にする。空なら undefined（項目を消す）。正しくなければ例外。
  function parse(f, s) {
    s = s.trim();
    if (s === "") return undefined;
    switch (f.type) {
      case "bool": return s === "true";
      case "number": {
        if (!/^-?\d+$/.test(s)) throw new Error("数で書いてください");
        return Number(s);
      }
      case "numbers": return splitList(s).map((v) => {
        if (!/^\d+$/.test(v)) throw new Error("数を「,」で区切って書いてください");
        return Number(v);
      });
      case "list": return splitList(s);
      case "objlist": {
        const old = getPath(state.obj, f.path);
        return splitList(s).map((v) => {
          const prev = Array.isArray(old) ? old.find((e) => e && e[f.key] === v) : undefined;
          return prev ? prev : { [f.key]: v };
        });
      }
      default: return s;
    }
  }

  function renderForm() {
    const form = $("form");
    form.replaceChildren();
    let fs = null, section = "";
    state.fields.forEach((f, i) => {
      if (f.section !== section) {
        section = f.section;
        fs = document.createElement("fieldset");
        const lg = document.createElement("legend");
        lg.textContent = section;
        fs.append(lg);
        form.append(fs);
      }
      const row = document.createElement("div");
      row.className = "field";
      const label = document.createElement("label");
      const id = "f" + i;
      label.htmlFor = id;
      label.textContent = f.label;
      let input;
      if (f.type === "bool") {
        input = document.createElement("select");
        [["", "既定"], ["true", "はい"], ["false", "いいえ"]].forEach(([v, t]) => {
          const o = document.createElement("option");
          o.value = v;
          o.textContent = t;
          input.append(o);
        });
      } else {
        input = document.createElement("input");
        input.type = "text";
        input.placeholder = f.placeholder || (f.type === "duration" ? "例: 30s、5m、1h" : "");
      }
      input.id = id;
      input.dataset.path = f.path;
      input.addEventListener("change", () => {
        try {
          setPath(state.obj, f.path, parse(f, input.value));
          input.classList.remove("bad");
          syncText();
        } catch (e) {
          input.classList.add("bad");
          showMessages([f.label + ": " + e.message], []);
        }
      });
      row.append(label, input);
      if (f.help) {
        const help = document.createElement("div");
        help.className = "help";
        help.textContent = f.help;
        row.append(help);
      }
      fs.append(row);
    });
    fillForm();
  }

  function fillForm() {
    state.fields.forEach((f, i) => {
      const input = $("f" + i);
      if (input) {
        input.value = shown(f, getPath(state.obj, f.path));
        input.classList.remove("bad");
      }
    });
  }

  function dirty() {
    state.checked = null;
    $("save").disabled = true;
  }

  function syncText() {
    $("json").value = JSON.stringify(state.obj, null, 2) + "\n";
    $("json-status").textContent = "";
    dirty();
  }

  function onJSONInput() {
    const st = $("json-status");
    dirty();
    try {
      const v = JSON.parse($("json").value);
      if (v === null || typeof v !== "object" || Array.isArray(v)) throw new Error("全体を { } のオブジェクトにしてください");
      state.obj = v;
      fillForm();
      st.textContent = "";
      st.classList.remove("bad");
    } catch (e) {
      st.textContent = "JSON の形が正しくありません: " + e.message;
      st.classList.add("bad");
    }
  }

  function list(items, cls) {
    const ul = document.createElement("ul");
    items.forEach((t) => {
      const li = document.createElement("li");
      li.className = cls;
      li.textContent = t;
      ul.append(li);
    });
    return ul;
  }

  function showMessages(errors, warnings, extra) {
    const r = $("result");
    r.replaceChildren();
    if (errors && errors.length) r.append(list(errors, "error"));
    if (warnings && warnings.length) r.append(list(warnings, "warn"));
    if (extra) r.append(...extra);
  }

  // diffView は変更のある行と、その前後 2 行だけを表示する。
  function diffView(diff) {
    const pre = document.createElement("pre");
    pre.className = "diff";
    const keep = new Array(diff.length).fill(false);
    diff.forEach((d, i) => {
      if (d.op !== " ") for (let j = Math.max(0, i - 2); j <= Math.min(diff.length - 1, i + 2); j++) keep[j] = true;
    });
    let gap = false;
    diff.forEach((d, i) => {
      if (!keep[i]) {
        if (!gap) {
          const s = document.createElement("span");
          s.className = "gap";
          s.textContent = "  …";
          pre.append(s);
        }
        gap = true;
        return;
      }
      gap = false;
      const s = document.createElement("span");
      s.className = d.op === "+" ? "add" : d.op === "-" ? "del" : "";
      s.textContent = d.op + " " + d.text;
      pre.append(s);
    });
    return pre;
  }

  function para(text, cls) {
    const p = document.createElement("p");
    p.className = cls || "";
    p.textContent = text;
    return p;
  }

  async function check() {
    const text = $("json").value;
    const { data } = await api("/api/check", { text });
    const extra = [];
    if (data.ok) extra.push(para(data.changed ? "検証に通りました。変更点を確かめてから保存してください。" : "検証に通りました。今の設定ファイルから変わっていません。", "ok"));
    if (data.diff && data.changed) extra.push(diffView(data.diff));
    showMessages(data.errors, data.warnings, extra);
    if (data.ok && data.changed) {
      state.checked = text;
      state.formatted = data.text;
      $("save").disabled = false;
    }
  }

  async function save() {
    if (state.checked === null || $("json").value !== state.checked) {
      showMessages(["確かめた後に変更があります。もう一度「確かめる」を押してください。"], []);
      dirty();
      return;
    }
    const { status, data } = await api("/api/save", { text: state.checked, hash: state.hash });
    if (!data.ok) {
      showMessages(data.errors, data.warnings, status === 409 ? [para("「読み込み直す」で最新の設定を読み込んでください。")] : []);
      return;
    }
    state.hash = data.hash;
    $("json").value = state.formatted;
    state.obj = JSON.parse(state.formatted);
    fillForm();
    dirty();
    const msgs = [para(data.unchanged ? "変わっていないため、保存しませんでした。" : "保存しました。前の設定の控え: " + data.backup, "ok")];
    if (state.service) msgs.push(para("設定は、サービス " + state.service + " を起動し直すと使われます。"));
    if (state.kind === "gw") msgs.push(para("GW は設定ファイルの変更を検知結果として記録します（意図した変更です）。"));
    showMessages([], data.warnings, msgs);
  }

  async function restart() {
    if (!state.service) return;
    if (!window.confirm("サービス " + state.service + " を起動し直しますか？ 起動し直す間（数秒）、" +
      (state.kind === "gw" ? "外部通信の制御はポリシーの on_failure に従います。" : "端末の監視は止まります（自己隔離は続きます）。"))) return;
    $("restart").disabled = true;
    const { data } = await api("/api/restart", {});
    $("restart").disabled = false;
    const extra = [para(data.ok ? "起動し直しました。状態: " + data.active : "状態: " + (data.active || "不明"), data.ok ? "ok" : "")];
    if (data.output) extra.push(para(data.output));
    showMessages(data.ok ? [] : data.errors, [], extra);
    showService(data.active);
  }

  function showService(active) {
    $("service").textContent = state.service ? "サービス " + state.service + "：" + (active || "不明") : "サービスは起動し直しません（-service none）";
  }

  async function load() {
    const { data } = await api("/api/config");
    if (data.ok === false) {
      showMessages(data.errors, []);
      return;
    }
    state.hash = data.hash;
    state.kind = data.kind;
    state.service = data.service;
    state.fields = data.fields;
    $("title").textContent = "susanoo の設定（" + (data.kind === "gw" ? "GW" : "CLIENT") + "）";
    $("file").textContent = "設定ファイル：" + data.path;
    showService(data.active);
    $("restart").disabled = !data.service;
    $("json").value = data.text;
    try {
      state.obj = JSON.parse(data.text);
    } catch (e) {
      state.obj = {};
      $("json-status").textContent = "今の設定ファイルを JSON として読めません。JSON の欄で直してください。";
      selectTab("json");
    }
    renderForm();
    dirty();
    showMessages([], []);
  }

  function selectTab(name) {
    const form = name === "form";
    $("pane-form").hidden = !form;
    $("pane-json").hidden = form;
    $("tab-form").setAttribute("aria-selected", String(form));
    $("tab-json").setAttribute("aria-selected", String(!form));
  }

  document.addEventListener("DOMContentLoaded", () => {
    $("tab-form").addEventListener("click", () => selectTab("form"));
    $("tab-json").addEventListener("click", () => selectTab("json"));
    $("json").addEventListener("input", onJSONInput);
    $("check").addEventListener("click", check);
    $("save").addEventListener("click", save);
    $("restart").addEventListener("click", restart);
    $("reload").addEventListener("click", load);
    $("form").addEventListener("submit", (e) => e.preventDefault());
    load();
  });
})();
