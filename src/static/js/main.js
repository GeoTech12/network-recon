"use strict";

// The dashboard calls /scan and renders the responsive hosts it returns.
// Every dynamic value is inserted with textContent / createElement and the
// results body is rebuilt with replaceChildren() -- innerHTML is never used for
// scan data. Nothing is stored in the browser.

document.addEventListener("DOMContentLoaded", function () {
  var checkbox = document.getElementById("authorized");
  var button = document.getElementById("scan-button");
  var stateEl = document.getElementById("scan-status");
  var resultsBody = document.getElementById("results-body");
  var summary = {
    network: document.getElementById("summary-network"),
    count: document.getElementById("summary-count"),
    ports: document.getElementById("summary-ports"),
    time: document.getElementById("summary-time"),
  };
  var COLUMN_COUNT = document.querySelectorAll(".results thead th").length || 5;

  function syncButton() {
    button.disabled = !checkbox.checked;
  }

  function setState(name, label, detail, showSpinner) {
    stateEl.className = "state state--" + name;
    stateEl.setAttribute("role", name === "error" ? "alert" : "status");
    stateEl.replaceChildren();

    if (showSpinner) {
      var dot = document.createElement("span");
      dot.className = "state__spinner";
      dot.setAttribute("aria-hidden", "true");
      stateEl.appendChild(dot);
    }
    var labelEl = document.createElement("span");
    labelEl.className = "state__label";
    labelEl.textContent = label;
    stateEl.appendChild(labelEl);

    var detailEl = document.createElement("span");
    detailEl.className = "state__detail";
    detailEl.textContent = detail;
    stateEl.appendChild(detailEl);
  }

  function placeholderRow(text) {
    var row = document.createElement("tr");
    var cell = document.createElement("td");
    cell.className = "results__empty";
    cell.colSpan = COLUMN_COUNT;
    cell.textContent = text;
    row.appendChild(cell);
    return row;
  }

  function resetSummary() {
    summary.network.textContent = "—";
    summary.count.textContent = "—";
    summary.ports.textContent = "—";
    summary.time.textContent = "—";
  }

  function formatScanTime(iso) {
    if (!iso) {
      return "—";
    }
    var parsed = new Date(iso);
    if (isNaN(parsed.getTime())) {
      return String(iso);
    }
    return parsed
      .toISOString()
      .replace("T", " ")
      .replace(/\.\d+Z$/, "Z")
      .replace("Z", " UTC");
  }

  // Cell specs: { text, muted?, mono? }. `muted` marks "information we do not
  // have"; real collected values are never muted.
  function hostnameCell(device, features) {
    if (device.hostname) {
      return { text: device.hostname };
    }
    if (features.hostname_resolution) {
      return { text: "Unknown", muted: true };
    }
    return { text: "Not resolved", muted: true };
  }

  function macCell(device) {
    if (device.mac) {
      return { text: device.mac, mono: true };
    }
    return { text: "Not available", muted: true };
  }

  function portsCell(device, features) {
    if (!features.port_check) {
      return { text: "Not checked", muted: true };
    }
    var ports = Array.isArray(device.open_ports) ? device.open_ports : [];
    if (ports.length === 0) {
      return { text: "None found", muted: true };
    }
    var text = ports
      .map(function (entry) {
        return entry.service
          ? entry.port + " (" + entry.service + ")"
          : String(entry.port);
      })
      .join(", ");
    return { text: text };
  }

  function appendCell(row, spec) {
    var cell = document.createElement("td");
    cell.textContent = spec.text;
    if (spec.muted) {
      cell.classList.add("cell--muted");
    }
    if (spec.mono) {
      cell.classList.add("cell--mono");
    }
    row.appendChild(cell);
  }

  function renderResults(data) {
    var features = data.features || {};
    var devices = Array.isArray(data.devices) ? data.devices : [];
    var count =
      typeof data.device_count === "number" ? data.device_count : devices.length;

    summary.network.textContent = data.network || "—";
    summary.count.textContent = String(count);
    summary.ports.textContent = features.port_check ? "On" : "Off";
    summary.time.textContent = formatScanTime(data.scan_time);

    if (devices.length === 0) {
      resultsBody.replaceChildren(
        placeholderRow(
          "Scan complete. No responsive hosts were found on " +
            (data.network || "the selected network") +
            "."
        )
      );
      return count;
    }

    var fragment = document.createDocumentFragment();
    devices.forEach(function (device) {
      var row = document.createElement("tr");
      appendCell(row, {
        text: device.ip || "—",
        mono: Boolean(device.ip),
      });
      appendCell(row, hostnameCell(device, features));
      appendCell(row, macCell(device));
      appendCell(row, { text: device.status || "unknown" });
      appendCell(row, portsCell(device, features));
      fragment.appendChild(row);
    });
    resultsBody.replaceChildren(fragment);
    return count;
  }

  checkbox.addEventListener("change", syncButton);
  syncButton();

  button.addEventListener("click", function () {
    setState(
      "scanning",
      "Scanning…",
      "Contacting hosts on your local network.",
      true
    );
    button.disabled = true;
    resultsBody.setAttribute("aria-busy", "true");
    resultsBody.replaceChildren(placeholderRow("Scanning…"));

    var body = new URLSearchParams();
    body.set("authorized", checkbox.checked ? "on" : "");

    fetch("/scan", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    })
      .then(function (response) {
        return response
          .json()
          .catch(function () {
            return null;
          })
          .then(function (data) {
            return { ok: response.ok, data: data };
          });
      })
      .then(function (result) {
        var data = result.data;
        if (result.ok && data && data.status === "ok") {
          var count = renderResults(data);
          var noun = count === 1 ? "host" : "hosts";
          setState(
            "completed",
            "Scan complete",
            count +
              " responsive " +
              noun +
              " on " +
              data.network +
              " (" +
              formatScanTime(data.scan_time) +
              ")."
          );
        } else {
          var message =
            (data && data.message) ||
            "The scan could not be completed. Please try again.";
          setState("error", "Error", message);
          resultsBody.replaceChildren(
            placeholderRow("The last scan did not complete.")
          );
          resetSummary();
        }
      })
      .catch(function () {
        setState(
          "error",
          "Error",
          "Could not reach the application. Is the server still running?"
        );
        resultsBody.replaceChildren(
          placeholderRow("The last scan did not complete.")
        );
        resetSummary();
      })
      .finally(function () {
        resultsBody.removeAttribute("aria-busy");
        syncButton();
      });
  });
});
