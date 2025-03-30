// PhishGuard - Options Page Script
// This script handles the options page functionality

// Declare chrome if it's not already defined (for testing environments)
if (typeof chrome === "undefined") {
  var chrome = {}
  chrome.storage = {
    sync: {
      get: (keys) =>
        new Promise((resolve) => {
          resolve({})
        }),
      set: (items) =>
        new Promise((resolve) => {
          resolve()
        }),
    },
    local: {
      get: (keys) =>
        new Promise((resolve) => {
          resolve({})
        }),
      set: (items) =>
        new Promise((resolve) => {
          resolve()
        }),
    },
  }
  chrome.runtime = {
    sendMessage: (message) =>
      new Promise((resolve) => {
        resolve()
      }),
  }
}

// Get DOM elements
const enablePhishTank = document.getElementById("enable-phishtank")
const enableSafeBrowsing = document.getElementById("enable-safebrowsing")
const enableCustomDb = document.getElementById("enable-custom-db")
const enableContentScanning = document.getElementById("enable-content-scanning")
const warningLevels = document.getElementsByName("warning-level")
const showEducationalTips = document.getElementById("show-educational-tips")
const phishTankApiKey = document.getElementById("phishtank-api-key")
const safeBrowsingApiKey = document.getElementById("safebrowsing-api-key")
const customApiKey = document.getElementById("custom-api-key")
const togglePhishTankKey = document.getElementById("toggle-phishtank-key")
const toggleSafeBrowsingKey = document.getElementById("toggle-safebrowsing-key")
const toggleCustomKey = document.getElementById("toggle-custom-key")
const enableStatistics = document.getElementById("enable-statistics")
const enableReporting = document.getElementById("enable-reporting")
const resetBtn = document.getElementById("reset-btn")
const saveBtn = document.getElementById("save-btn")
const statusMessage = document.getElementById("status-message")

// Load settings when the page loads
document.addEventListener("DOMContentLoaded", loadSettings)

// Function to load settings from storage
async function loadSettings() {
  try {
    // Get settings from storage
    const data = await chrome.storage.sync.get("settings")

    if (data.settings) {
      const settings = data.settings

      // Set checkbox values
      enablePhishTank.checked = settings.enablePhishTankCheck !== false
      enableSafeBrowsing.checked = settings.enableSafeBrowsingCheck !== false
      enableCustomDb.checked = settings.enableCustomDatabaseCheck !== false
      enableContentScanning.checked = settings.enableContentScanning !== false
      showEducationalTips.checked = settings.showEducationalTips !== false

      // Set warning level radio button
      for (const radio of warningLevels) {
        if (radio.value === settings.warningLevel) {
          radio.checked = true
          break
        }
      }

      // Set data & privacy options
      enableStatistics.checked = settings.enableStatistics !== false
      enableReporting.checked = settings.enableReporting !== false
    }

    // Get API keys from storage
    const apiKeys = await chrome.storage.local.get("apiKeys")

    if (apiKeys.apiKeys) {
      // Set API key input values
      phishTankApiKey.value = apiKeys.apiKeys.phishTank || ""
      safeBrowsingApiKey.value = apiKeys.apiKeys.safeBrowsing || ""
      customApiKey.value = apiKeys.apiKeys.customDatabase || ""
    }
  } catch (error) {
    console.error("Error loading settings:", error)
    showStatus("Error loading settings. Please try again.", "error")
  }
}

// Function to save settings to storage
async function saveSettings() {
  try {
    // Get warning level value
    let warningLevel = "medium" // Default
    for (const radio of warningLevels) {
      if (radio.checked) {
        warningLevel = radio.value
        break
      }
    }

    // Create settings object
    const settings = {
      enablePhishTankCheck: enablePhishTank.checked,
      enableSafeBrowsingCheck: enableSafeBrowsing.checked,
      enableCustomDatabaseCheck: enableCustomDb.checked,
      enableContentScanning: enableContentScanning.checked,
      warningLevel: warningLevel,
      showEducationalTips: showEducationalTips.checked,
      enableStatistics: enableStatistics.checked,
      enableReporting: enableReporting.checked,
    }

    // Save settings to storage
    await chrome.storage.sync.set({ settings })

    // Create API keys object
    const apiKeys = {
      phishTank: phishTankApiKey.value.trim(),
      safeBrowsing: safeBrowsingApiKey.value.trim(),
      customDatabase: customApiKey.value.trim(),
    }

    // Save API keys to storage
    await chrome.storage.local.set({ apiKeys })

    // Notify background script of settings change
    chrome.runtime.sendMessage({
      action: "updateSettings",
      settings: settings,
    })

    showStatus("Settings saved successfully!", "success")
  } catch (error) {
    console.error("Error saving settings:", error)
    showStatus("Error saving settings. Please try again.", "error")
  }
}

// Function to reset settings to defaults
async function resetSettings() {
  try {
    // Default settings
    const defaultSettings = {
      enablePhishTankCheck: true,
      enableSafeBrowsingCheck: true,
      enableCustomDatabaseCheck: true,
      enableContentScanning: true,
      warningLevel: "medium",
      showEducationalTips: true,
      enableStatistics: true,
      enableReporting: true,
    }

    // Save default settings to storage
    await chrome.storage.sync.set({ settings: defaultSettings })

    // Clear API keys
    await chrome.storage.local.set({ apiKeys: {} })

    // Reload settings in the UI
    loadSettings()

    // Notify background script of settings change
    chrome.runtime.sendMessage({
      action: "updateSettings",
      settings: defaultSettings,
    })

    showStatus("Settings reset to defaults.", "success")
  } catch (error) {
    console.error("Error resetting settings:", error)
    showStatus("Error resetting settings. Please try again.", "error")
  }
}

// Function to show status message
function showStatus(message, type) {
  statusMessage.textContent = message
  statusMessage.className = `status-message ${type}`
  statusMessage.style.display = "block"

  // Hide message after 3 seconds
  setTimeout(() => {
    statusMessage.style.display = "none"
  }, 3000)
}

// Event listeners for toggle API key visibility buttons
togglePhishTankKey.addEventListener("click", () => {
  togglePasswordVisibility(phishTankApiKey, togglePhishTankKey)
})

toggleSafeBrowsingKey.addEventListener("click", () => {
  togglePasswordVisibility(safeBrowsingApiKey, toggleSafeBrowsingKey)
})

toggleCustomKey.addEventListener("click", () => {
  togglePasswordVisibility(customApiKey, toggleCustomKey)
})

// Function to toggle password visibility
function togglePasswordVisibility(input, button) {
  if (input.type === "password") {
    input.type = "text"
    button.textContent = "Hide"
  } else {
    input.type = "password"
    button.textContent = "Show"
  }
}

// Event listeners for buttons
saveBtn.addEventListener("click", saveSettings)
resetBtn.addEventListener("click", resetSettings)

