// background.js
chrome.webRequest.onBeforeRequest.addListener(
  async (details) => {
    const url = details.url;
    const apiKey = "YOUR_API_KEY_HERE"; // Placeholder for API key
    //please note, i did not put any API keys to for security reasons, prior to launch of the project api keys will be add

    // Example of checking against a phishing database (PhishTank or Google Safe Browsing API)
    const response = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`, {
      method: 'POST',
      body: JSON.stringify({
        client: {
          clientId: "phishing-extension",
          clientVersion: "1.0"
        },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url }]
        }
      }),
      headers: {
        'Content-Type': 'application/json'
      }
    });// PhishGuard - Background Service Worker
// This script runs in the background and handles URL checking against phishing databases

// Configuration for API endpoints
const CONFIG = {
  // PhishTank API configuration
  phishTank: {
    apiUrl: "https://checkurl.phishtank.com/checkurl/",
    // API key placeholder - to be filled by the user
    apiKey: "/* PHISHTANK_API_KEY */",
  },

  // Google Safe Browsing API configuration
  safeBrowsing: {
    apiUrl: "https://safebrowsing.googleapis.com/v4/threatMatches:find",
    // API key placeholder - to be filled by the user
    apiKey: "/* GOOGLE_SAFE_BROWSING_API_KEY */",
  },

  // Custom database of Nigeria-specific phishing sites (could be hosted on your server)
  customDatabase: {
    apiUrl: "https://api.thinkcybernigeria.com/phishing-db/check",
    // API key placeholder - to be filled by the user
    apiKey: "/* CUSTOM_API_KEY */",
  },
}

// Initialize extension settings
let settings = {
  enablePhishTankCheck: true,
  enableSafeBrowsingCheck: true,
  enableCustomDatabaseCheck: true,
  enableContentScanning: true,
  warningLevel: "medium", // 'low', 'medium', 'high'
  showEducationalTips: true,
}

// Load settings from storage when extension starts
chrome.storage.sync.get("settings", (data) => {
  if (data.settings) {
    settings = { ...settings, ...data.settings }
  } else {
    // Save default settings if none exist
    chrome.storage.sync.set({ settings })
  }
})

// Listen for navigation events to check URLs before page loads
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // Only check main frame navigations (not iframes, etc.)
  if (details.frameId === 0) {
    const url = details.url
    const tabId = details.tabId

    // Skip checking for known safe domains
    if (isKnownSafeDomain(url)) {
      return
    }

    // Check the URL against phishing databases
    const checkResults = await checkUrl(url)

    // If the URL is flagged as phishing, show a warning
    if (checkResults.isPhishing) {
      // Update the extension icon to show a warning
      updateExtensionIcon(tabId, "warning")

      // Show a warning notification
      showPhishingWarning(tabId, url, checkResults.reasons)
    }
  }
})

// Function to check if a domain is in our known safe list
function isKnownSafeDomain(url) {
  try {
    const hostname = new URL(url).hostname

    // List of known safe domains (could be expanded or loaded from storage)
    const safeDomains = [
      "google.com",
      "google.com.ng",
      "facebook.com",
      "twitter.com",
      "instagram.com",
      "linkedin.com",
      "microsoft.com",
      "apple.com",
      "amazon.com",
      // Nigerian banks and government sites
      "cbn.gov.ng",
      "gtbank.com",
      "firstbanknigeria.com",
      "accessbankplc.com",
      "zenithbank.com",
      "nigeriangovernment.gov.ng",
    ]

    // Check if the hostname matches or is a subdomain of a safe domain
    return safeDomains.some((domain) => hostname === domain || hostname.endsWith("." + domain))
  } catch (error) {
    console.error("Error parsing URL:", error)
    return false
  }
}

// Function to check a URL against multiple phishing databases
async function checkUrl(url) {
  const results = {
    isPhishing: false,
    reasons: [],
    sources: [],
  }

  // Check URL format for common phishing indicators
  const urlIndicators = checkUrlForPhishingIndicators(url)
  if (urlIndicators.suspicious) {
    results.isPhishing = true
    results.reasons.push(...urlIndicators.reasons)
    results.sources.push("url_analysis")
  }

  // Check against PhishTank if enabled
  if (settings.enablePhishTankCheck) {
    try {
      const phishTankResult = await checkPhishTank(url)
      if (phishTankResult.isPhishing) {
        results.isPhishing = true
        results.reasons.push("URL found in PhishTank database")
        results.sources.push("phishtank")
      }
    } catch (error) {
      console.error("PhishTank check error:", error)
    }
  }

  // Check against Google Safe Browsing if enabled
  if (settings.enableSafeBrowsingCheck) {
    try {
      const safeBrowsingResult = await checkGoogleSafeBrowsing(url)
      if (safeBrowsingResult.isPhishing) {
        results.isPhishing = true
        results.reasons.push("URL flagged by Google Safe Browsing")
        results.sources.push("google_safe_browsing")
      }
    } catch (error) {
      console.error("Google Safe Browsing check error:", error)
    }
  }

  // Check against custom database if enabled
  if (settings.enableCustomDatabaseCheck) {
    try {
      const customDbResult = await checkCustomDatabase(url)
      if (customDbResult.isPhishing) {
        results.isPhishing = true
        results.reasons.push("URL found in Nigeria-specific phishing database")
        results.sources.push("custom_database")
      }
    } catch (error) {
      console.error("Custom database check error:", error)
    }
  }

  // Log the check results
  console.log("PhishGuard check results for", url, results)

  return results
}

// Function to check URL for common phishing indicators
function checkUrlForPhishingIndicators(url) {
  const result = {
    suspicious: false,
    reasons: [],
  }

  try {
    const parsedUrl = new URL(url)
    const hostname = parsedUrl.hostname

    // Check for IP address instead of domain name
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(hostname)) {
      result.suspicious = true
      result.reasons.push("URL uses IP address instead of domain name")
    }

    // Check for suspicious TLDs
    const suspiciousTLDs = [".tk", ".ml", ".ga", ".cf", ".gq"]
    if (suspiciousTLDs.some((tld) => hostname.endsWith(tld))) {
      result.suspicious = true
      result.reasons.push("URL uses suspicious top-level domain")
    }

    // Check for excessive subdomains
    const subdomainCount = hostname.split(".").length - 2
    if (subdomainCount > 3) {
      result.suspicious = true
      result.reasons.push("URL has an unusual number of subdomains")
    }

    // Check for common brand names in subdomain (potential spoofing)
    const commonBrands = [
      "paypal",
      "apple",
      "microsoft",
      "amazon",
      "netflix",
      "facebook",
      "google",
      "gtbank",
      "zenith",
      "access",
    ]
    for (const brand of commonBrands) {
      if (hostname.includes(brand) && !hostname.startsWith(brand + ".")) {
        result.suspicious = true
        result.reasons.push(`URL may be spoofing ${brand}`)
        break
      }
    }

    // Check for suspicious URL patterns
    if (url.includes("login") && url.includes("redirect")) {
      result.suspicious = true
      result.reasons.push("URL contains suspicious login and redirect patterns")
    }

    // Check for unusual port numbers
    if (parsedUrl.port && parsedUrl.port !== "80" && parsedUrl.port !== "443") {
      result.suspicious = true
      result.reasons.push("URL uses unusual port number")
    }

    // Check for excessive use of special characters in path
    const specialCharsCount = (parsedUrl.pathname.match(/[^\w/.-]/g) || []).length
    if (specialCharsCount > 5) {
      result.suspicious = true
      result.reasons.push("URL path contains many special characters")
    }
  } catch (error) {
    console.error("Error analyzing URL:", error)
  }

  return result
}

// Function to check URL against PhishTank database
async function checkPhishTank(url) {
  // Skip if API key is not set
  if (CONFIG.phishTank.apiKey === "/* PHISHTANK_API_KEY */") {
    console.warn("PhishTank API key not configured")
    return { isPhishing: false }
  }

  try {
    const response = await fetch(CONFIG.phishTank.apiUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "PhishGuard Chrome Extension",
      },
      body: `url=${encodeURIComponent(url)}&format=json&app_key=${CONFIG.phishTank.apiKey}`,
    })

    if (!response.ok) {
      throw new Error(`PhishTank API error: ${response.status}`)
    }

    const data = await response.json()

    return {
      isPhishing: data.results.in_database && data.results.phish_detail_page,
      confidence: data.results.in_database ? "high" : "unknown",
      details: data.results,
    }
  } catch (error) {
    console.error("PhishTank check failed:", error)
    return { isPhishing: false }
  }
}

// Function to check URL against Google Safe Browsing API
async function checkGoogleSafeBrowsing(url) {
  // Skip if API key is not set
  if (CONFIG.safeBrowsing.apiKey === "/* GOOGLE_SAFE_BROWSING_API_KEY */") {
    console.warn("Google Safe Browsing API key not configured")
    return { isPhishing: false }
  }

  try {
    const requestBody = {
      client: {
        clientId: "PhishGuard",
        clientVersion: "1.0.0",
      },
      threatInfo: {
        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url: url }],
      },
    }

    const response = await fetch(`${CONFIG.safeBrowsing.apiUrl}?key=${CONFIG.safeBrowsing.apiKey}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(requestBody),
    })

    if (!response.ok) {
      throw new Error(`Google Safe Browsing API error: ${response.status}`)
    }

    const data = await response.json()

    return {
      isPhishing: data.matches && data.matches.length > 0,
      confidence: data.matches && data.matches.length > 0 ? "high" : "unknown",
      details: data.matches || [],
    }
  } catch (error) {
    console.error("Google Safe Browsing check failed:", error)
    return { isPhishing: false }
  }
}

// Function to check URL against custom Nigeria-specific database
async function checkCustomDatabase(url) {
  // Skip if API key is not set
  if (CONFIG.customDatabase.apiKey === "/* CUSTOM_API_KEY */") {
    console.warn("Custom database API key not configured")
    return { isPhishing: false }
  }

  try {
    const response = await fetch(CONFIG.customDatabase.apiUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${CONFIG.customDatabase.apiKey}`,
      },
      body: JSON.stringify({ url }),
    })

    if (!response.ok) {
      throw new Error(`Custom database API error: ${response.status}`)
    }

    const data = await response.json()

    return {
      isPhishing: data.isPhishing,
      confidence: data.confidence || "unknown",
      details: data.details || {},
    }
  } catch (error) {
    console.error("Custom database check failed:", error)
    return { isPhishing: false }
  }
}

// Function to update the extension icon based on the current status
function updateExtensionIcon(tabId, status) {
  let iconPath

  switch (status) {
    case "warning":
      iconPath = {
        16: "images/icon16_warning.png",
        48: "images/icon48_warning.png",
        128: "images/icon128_warning.png",
      }
      break
    case "danger":
      iconPath = {
        16: "images/icon16_danger.png",
        48: "images/icon48_danger.png",
        128: "images/icon128_danger.png",
      }
      break
    default:
      iconPath = {
        16: "images/icon16.png",
        48: "images/icon48.png",
        128: "images/icon128.png",
      }
  }

  chrome.action.setIcon({ tabId, path: iconPath })
}

// Function to show a phishing warning to the user
function showPhishingWarning(tabId, url, reasons) {
  // Store the warning details for this tab
  chrome.storage.local.set({
    [`warning_${tabId}`]: {
      url,
      reasons,
      timestamp: Date.now(),
    },
  })

  // Show a notification
  chrome.notifications.create({
    type: "basic",
    iconUrl: "images/icon128_warning.png",
    title: "PhishGuard Warning",
    message: `Potential phishing site detected: ${new URL(url).hostname}`,
    contextMessage: reasons[0] || "This site may be trying to steal your information",
    buttons: [{ title: "View Details" }, { title: "Ignore" }],
    priority: 2,
  })

  // Inject warning overlay into the page
  chrome.tabs.sendMessage(tabId, {
    action: "showWarning",
    url,
    reasons,
  })
}

// Listen for messages from content scripts or popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "checkUrl") {
    checkUrl(message.url)
      .then((results) => sendResponse(results))
      .catch((error) => {
        console.error("Error checking URL:", error)
        sendResponse({ isPhishing: false, error: error.message })
      })
    return true // Required for async sendResponse
  }

  if (message.action === "getSettings") {
    sendResponse({ settings })
    return true
  }

  if (message.action === "updateSettings") {
    settings = { ...settings, ...message.settings }
    chrome.storage.sync.set({ settings })
    sendResponse({ success: true })
    return true
  }

  if (message.action === "reportPhishing") {
    // Handle user-reported phishing site
    reportPhishingSite(message.url, message.details)
      .then((result) => sendResponse(result))
      .catch((error) => sendResponse({ success: false, error: error.message }))
    return true
  }
})

// Function to report a phishing site to our database
async function reportPhishingSite(url, details) {
  try {
    // This would send the report to your server
    const response = await fetch("https://api.thinkcybernigeria.com/phishing-db/report", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${CONFIG.customDatabase.apiKey}`,
      },
      body: JSON.stringify({
        url,
        reportedBy: "extension_user",
        details,
      }),
    })

    if (!response.ok) {
      throw new Error(`Report submission failed: ${response.status}`)
    }

    const data = await response.json()
    return { success: true, data }
  } catch (error) {
    console.error("Error reporting phishing site:", error)
    return { success: false, error: error.message }
  }
}

// Listen for installation or update
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === "install") {
    // Show welcome page on install
    chrome.tabs.create({ url: "index.html" })
  } else if (details.reason === "update") {
    // Show update notification
    chrome.notifications.create({
      type: "basic",
      iconUrl: "images/icon128.png",
      title: "PhishGuard Updated",
      message: "Your phishing protection has been updated with the latest security features.",
      priority: 1,
    })
  }
})



    const data = await response.json();

    if (data.matches) {
      chrome.notifications.create({
        type: "basic",
        iconUrl: "icon.png",
        title: "Phishing Alert!",
        message: "This website has been flagged as a potential phishing site. Proceed with caution."
      });
      return { cancel: true };
    }
  },
  { urls: ["<all_urls>"] },
  ["blocking"]
);
