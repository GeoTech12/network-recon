"use strict";

// Milestone 1: the scan action only calls the placeholder endpoint and shows
// its response. No real reconnaissance is performed anywhere in the client.

document.addEventListener("DOMContentLoaded", function () {
  var checkbox = document.getElementById("authorized");
  var button = document.getElementById("scan-button");
  var statusEl = document.getElementById("scan-status");

  function syncButton() {
    button.disabled = !checkbox.checked;
  }

  function setStatus(message, isError) {
    statusEl.textContent = message;
    statusEl.classList.toggle("status--error", Boolean(isError));
  }

  checkbox.addEventListener("change", syncButton);
  syncButton();

  button.addEventListener("click", function () {
    setStatus("Starting scan…", false);
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
