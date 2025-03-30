// PhishGuard - Popup Script
// This script handles the popup UI and interactions

// Get DOM elements
const statusDot = document.getElementById("status-dot")
const statusText = document.getElementById("status-text")
const currentUrl = document.getElementById("current-url")
const sitesChecked = document.getElementById("sites-checked")
const threatsBlocked = document.getElementById("threats-blocked")
const daysActive = document.getElementById("days-active")
const warningDetails = document.getElementById("warning-details")
const warningReasons = document.getElementById("warning-reasons")
const securityTip = document.getElementById("security-tip")
const scanPageBtn = document.getElementById("scan-page-btn")
const reportSiteBtn = document.getElementById("report-site-btn")
const settingsBtn = document.getElementById("settings-btn")
const helpLink = document.getElementById("help-link")
const privacyLink = document.getElementById("privacy-link")

// Security tips to display randomly
const securityTips = [
  "Always check the URL before entering sensitive information. Legitimate websites use secure connections (https://).",
  "Be cautious of emails asking for personal information, even if they appear to be from trusted sources.",
  "Use unique, strong passwords for different accounts. Consider using a password manager.",
  "Enable two-factor authentication whenever possible for added security.",
  "Hover over links before clicking to see where they actually lead.",
  "Be wary of websites with poor grammar, spelling errors, or unprofessional design.",
  "Check for a padlock icon in your browser's address bar before entering sensitive information.",
  "Legitimate organizations won't ask for sensitive information via email or text message.",
  "Keep your browser and extensions updated to protect against known vulnerabilities.",
  "If a deal seems too good to be true, it probably is. Be skeptical of extraordinary offers.",
]

// Display a random security tip
securityTip.textContent = securityTips[Math.floor(Math.random() * securityTips.length)]

// Initialize popup when opened
document.addEventListener("DOMContentLoaded", async () => {
  // Get current tab information
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true })
  const currentTab = tabs[0]

  // Display current URL
  if (currentTab && currentTab.url) {
    try {
      const url = new URL(currentTab.url)
      currentUrl.textContent = url.hostname

      // Check if this site has any warnings
      checkCurrentSite(currentTab.url, currentTab.id)
    } catch (error) {
      console.error("Error parsing URL:", error)
      currentUrl.textContent = "Invalid URL"
    }
  } else {
    currentUrl.textContent = "No URL available"
  }

  // Load statistics
  loadStatistics()
})

// Function to check current site status
async function checkCurrentSite(url, tabId) {
  try {
    // Check if there's a warning for this tab
    const warningKey = `warning_${tabId}`
    const data = await chrome.storage.local.get(warningKey)

    if (data[warningKey]) {
      // There's a warning for this site
      const warning = data[warningKey]

      // Update status indicator
      statusDot.className = "status-dot danger"
      statusText.textContent = "Potential phishing site detected"

      // Show warning details
      warningDetails.style.display = "block"
      warningReasons.innerHTML = ""

      // Add warning reasons
      if (warning.reasons && warning.reasons.length > 0) {
        warning.reasons.forEach((reason) => {
          const li = document.createElement("li")
          li.textContent = reason
          warningReasons.appendChild(li)
        })
      } else {
        const li = document.createElement("li")
        li.textContent = "This site matches patterns commonly used in phishing attacks."
        warningReasons.appendChild(li)
      }
    } else {
      // No warning, check URL against phishing databases
      const response = await chrome.runtime.sendMessage({
        action: "checkUrl",
        url: url,
      })

      if (response.isPhishing) {
        // URL is flagged as phishing
        statusDot.className = "status-dot danger"
        statusText.textContent = "Potential phishing site detected"

        // Show warning details
        warningDetails.style.display = "block"
        warningReasons.innerHTML = ""

        // Add warning reasons
        if (response.reasons && response.reasons.length > 0) {
          response.reasons.forEach((reason) => {
            const li = document.createElement("li")
            li.textContent = reason
            warningReasons.appendChild(li)
          })
        } else {
          const li = document.createElement("li")
          li.textContent = "This site matches patterns commonly used in phishing attacks."
          warningReasons.appendChild(li)
        }
      } else {
        // URL appears safe
        statusDot.className = "status-dot safe"
        statusText.textContent = "This site appears safe"
        warningDetails.style.display = "none"
      }
    }
  } catch (error) {
    console.error("Error checking site status:", error)
    statusDot.className = "status-dot warning"
    statusText.textContent = "Could not verify site safety"
    warningDetails.style.display = "none"
  }
}

// Function to load statistics
async function loadStatistics() {
  try {
    const stats = await chrome.storage.local.get("statistics")

    if (stats.statistics) {
      sitesChecked.textContent = stats.statistics.sitesChecked || 0
      threatsBlocked.textContent = stats.statistics.threatsBlocked || 0

      // Calculate days active
      const installDate = stats.statistics.installDate || Date.now()
      const daysSinceInstall = Math.floor((Date.now() - installDate) / (1000 * 60 * 60 * 24))
      daysActive.textContent = daysSinceInstall
    } else {
      // Initialize statistics if they don't exist
      const newStats = {
        sitesChecked: 0,
        threatsBlocked: 0,
        installDate: Date.now(),
      }

      await chrome.storage.local.set({ statistics: newStats })

      sitesChecked.textContent = "0"
      threatsBlocked.textContent = "0"
      daysActive.textContent = "0"
    }
  } catch (error) {
    console.error("Error loading statistics:", error)
  }
}

// Event listeners for buttons
scanPageBtn.addEventListener("click", async () => {
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true })
    const currentTab = tabs[0]

    if (currentTab && currentTab.id) {
      // Show scanning status
      statusDot.className = "status-dot warning"
      statusText.textContent = "Scanning page..."

      // Send message to content script to scan the page
      chrome.tabs.sendMessage(currentTab.id, { action: "scanPage" }, (response) => {
        if (chrome.runtime.lastError) {
          console.error("Error sending message:", chrome.runtime.lastError)
          statusText.textContent = "Could not scan page"
          return
        }

        if (response && response.success) {
          // Update statistics
          updateStatistic("sitesChecked", 1)

          // Refresh the popup
          checkCurrentSite(currentTab.url, currentTab.id)
        }
      })
    }
  } catch (error) {
    console.error("Error scanning page:", error)
  }
})

reportSiteBtn.addEventListener("click", async () => {
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true })
    const currentTab = tabs[0]

    if (currentTab && currentTab.url) {
      // Open the report page
      chrome.tabs.create({
        url: `report.html?url=${encodeURIComponent(currentTab.url)}`,
      })
    }
  } catch (error) {
    console.error("Error opening report page:", error)
  }
})

settingsBtn.addEventListener("click", () => {
  // Open the options page
  chrome.runtime.openOptionsPage()
})

helpLink.addEventListener("click", () => {
  // Open the help page
  chrome.tabs.create({
    url: "help.html",
  })
})

privacyLink.addEventListener("click", () => {
  // Open the privacy policy page
  chrome.tabs.create({
    url: "privacy.html",
  })
})

// Function to update a statistic
async function updateStatistic(key, increment) {
  try {
    const stats = await chrome.storage.local.get("statistics")

    if (stats.statistics) {
      stats.statistics[key] = (stats.statistics[key] || 0) + increment
      await chrome.storage.local.set({ statistics: stats.statistics })
    }
  } catch (error) {
    console.error("Error updating statistics:", error)
  }
}

