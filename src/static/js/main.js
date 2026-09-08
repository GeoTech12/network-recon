"use strict";

// Milestone 2: the scan calls the discovery endpoint and renders the responsive
// hosts it returns. Hostname, MAC and port columns are placeholders that later
// milestones will fill in.

document.addEventListener("DOMContentLoaded", function () {
  var checkbox = document.getElementById("authorized");
  var button = document.getElementById("scan-button");
  var statusEl = document.getElementById("scan-status");
  var networkEl = document.getElementById("scan-network");
  var resultsBody = document.getElementById("results-body");

  var PENDING = "Not collected yet";

  function syncButton() {
    button.disabled = !checkbox.checked;
  }

  function setStatus(message, isError) {
    statusEl.textContent = message;
    statusEl.classList.toggle("status--error", Boolean(isError));
  }

  function clearResults(message) {
    resultsBody.innerHTML = "";
    var row = document.createElement("tr");
    var cell = document.createElement("td");
    cell.className = "results__empty";
    cell.colSpan = 6;
    cell.textContent = message;
    row.appendChild(cell);
    resultsBody.appendChild(row);
  }

  function renderResults(data) {
    networkEl.textContent = data.network || "—";

    var devices = Array.isArray(data.devices) ? data.devices : [];
    if (devices.length === 0) {
      clearResults("No responsive hosts found.");
      return;
    }

    resultsBody.innerHTML = "";
    devices.forEach(function (device) {
      var row = document.createElement("tr");
      [
        device.ip || "—",
        device.hostname || "Unknown",
        device.mac || "Not available",
        device.status || "unknown",
        PENDING,
        data.scan_time || "—",
      ].forEach(function (value) {
        var cell = document.createElement("td");
        cell.textContent = value;
        row.appendChild(cell);
      });
      resultsBody.appendChild(row);
    });
  }

  checkbox.addEventListener("change", syncButton);
  syncButton();

  button.addEventListener("click", function () {
    setStatus("Scanning your local network…", false);
    button.disabled = true;

    var body = new URLSearchParams();
    body.set("authorized", checkbox.checked ? "on" : "");

    fetch("/scan", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    })
      .then(function (response) {
        return response.json().then(function (data) {
          return { ok: response.ok, data: data };
        });
      })
      .then(function (result) {
        setStatus(
          result.data.message || "Unexpected response from the server.",
          !result.ok
        );
        if (result.ok && result.data.status === "ok") {
          renderResults(result.data);
        }
      })
      .catch(function () {
        setStatus(
          "Could not reach the application. Is the server still running?",
          true
        );
      })
      .finally(function () {
        syncButton();
      });
  });
});
