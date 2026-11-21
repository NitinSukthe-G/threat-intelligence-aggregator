(function () {
  "use strict";

  function toast(message) {
    var el = document.createElement("div");
    el.className = "toast";
    el.textContent = message;
    document.body.appendChild(el);
    setTimeout(function () { el.remove(); }, 3500);
  }

  function el(tag, text, className) {
    var node = document.createElement(tag);
    if (text !== undefined) node.textContent = text;
    if (className) node.className = className;
    return node;
  }

  // Expand / collapse IOC detail rows and copy buttons.
  document.addEventListener("click", function (event) {
    var toggle = event.target.closest(".toggle");
    if (toggle) {
      var detail = toggle.closest("tr").nextElementSibling;
      detail.hidden = !detail.hidden;
      toggle.textContent = detail.hidden ? "▾" : "▴";
      return;
    }
    var copy = event.target.closest("[data-copy]");
    if (copy && navigator.clipboard) {
      navigator.clipboard.writeText(copy.dataset.copy).then(
        function () { toast("Copied to clipboard"); },
        function () { toast("Copy failed"); }
      );
    }
  });

  // Pipeline run button with polling.
  var runBtn = document.getElementById("run-btn");
  var liveText = document.getElementById("live-text");
  var livePill = document.getElementById("live-pill");

  var attempts = 0;

  function poll() {
    if (++attempts > 90) return;
    fetch("/api/status", { cache: "no-store" }).then(function (r) { return r.json(); }).then(function (s) {
      if (s.running) {
        livePill.dataset.running = "true";
        liveText.textContent = "Pipeline running…";
        setTimeout(poll, 3000);
      } else {
        window.location.reload();
      }
    }).catch(function () { setTimeout(poll, 5000); });
  }

  if (runBtn) {
    var cooldown = parseInt(runBtn.dataset.cooldown || "0", 10);
    if (cooldown > 0) runBtn.title = "Available again in about " + cooldown + "s";

    runBtn.addEventListener("click", function () {
      var headers = {};
      if (runBtn.dataset.needsToken === "true") {
        var token = window.prompt("Admin token required to run the pipeline:");
        if (!token) return;
        headers["X-Admin-Token"] = token;
      }
      runBtn.disabled = true;
      fetch("/api/run", { method: "POST", headers: headers }).then(function (r) {
        return r.json().then(function (body) { return { status: r.status, body: body }; });
      }).then(function (res) {
        if (res.status === 202 || res.status === 409) {
          toast(res.status === 202 ? "Pipeline started" : "A run is already in progress");
          poll();
        } else {
          toast(res.body.message || res.body.error || "Could not start the pipeline");
          runBtn.disabled = false;
        }
      }).catch(function () { toast("Network error"); runBtn.disabled = false; });
    });

    if (livePill && livePill.dataset.running === "true") poll();
  }

  // Auto-refresh while the very first snapshot is being built.
  if (document.querySelector(".empty-hero .loader")) setTimeout(poll, 4000);

  // Indicator lookup (DOM built with textContent only - no HTML injection).
  var form = document.getElementById("lookup-form");
  if (form) {
    form.addEventListener("submit", function (event) {
      event.preventDefault();
      var query = document.getElementById("lookup-input").value.trim();
      var box = document.getElementById("lookup-result");
      if (!query) return;
      fetch("/api/lookup?q=" + encodeURIComponent(query)).then(function (r) { return r.json(); }).then(function (d) {
        box.hidden = false;
        box.className = "lookup-result";
        box.replaceChildren();
        if (d.error) { box.appendChild(el("b", d.error)); return; }
        if (!d.valid) { box.appendChild(el("b", d.message)); return; }
        if (!d.found) {
          box.classList.add("clean");
          box.appendChild(el("b", "No match for " + d.type + " " + d.normalized));
          box.appendChild(el("p", "Not present in the current aggregated intelligence. This is not proof that it is safe.", "muted small"));
          return;
        }
        box.classList.add("hit");
        var m = d.match;
        if (m) {
          box.appendChild(el("b", m.risk_level + " risk (" + m.risk_score + "/100) — " + d.type + " " + d.normalized));
          box.appendChild(el("p", "Reported by: " + m.sources.join(", ") + (m.malware ? " · " + m.malware : ""), "muted small"));
          var list = el("ul");
          (m.risk_reasons || []).forEach(function (reason) { list.appendChild(el("li", reason)); });
          box.appendChild(list);
        }
        (d.netblocks || []).forEach(function (n) {
          box.appendChild(el("p", "Inside listed netblock " + n.indicator + " (" + n.sources.join(", ") + ")", "small"));
        });
      }).catch(function () { toast("Lookup failed"); });
    });
  }
})();
