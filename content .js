// PhishGuard - Content Script
// This script runs in the context of web pages and analyzes their content for phishing indicators

// Initialize when the page is fully loaded
document.addEventListener("DOMContentLoaded", () => {
  // Get settings from background script
  chrome.runtime.sendMessage({ action: "getSettings" }, (response) => {
    if (response && response.settings && response.settings.enableContentScanning) {
      // Analyze the page for phishing indicators
      analyzePageContent()
    }
  })
})

// Function to analyze page content for phishing indicators
async function analyzePageContent() {
  const results = {
    suspicious: false,
    reasons: [],
    confidence: "low",
  }

  // Check for login forms
  const loginFormResults = checkForLoginForms()
  if (loginFormResults.suspicious) {
    results.suspicious = true
    results.reasons.push(...loginFormResults.reasons)

    // Increase confidence level if multiple indicators are found
    if (loginFormResults.reasons.length > 1) {
      results.confidence = "medium"
    }
  }

  // Check for brand impersonation
  const brandResults = checkForBrandImpersonation()
  if (brandResults.suspicious) {
    results.suspicious = true
    results.reasons.push(...brandResults.reasons)

    // Brand impersonation is a strong indicator
    if (results.confidence !== "high") {
      results.confidence = "medium"
    }
  }

  // Check for SSL/TLS issues
  const sslResults = checkForSSLIssues()
  if (sslResults.suspicious) {
    results.suspicious = true
    results.reasons.push(...sslResults.reasons)
  }

  // Check for suspicious redirects
  const redirectResults = checkForSuspiciousRedirects()
  if (redirectResults.suspicious) {
    results.suspicious = true
    results.reasons.push(...redirectResults.reasons)
    results.confidence = "high" // Suspicious redirects are a strong indicator
  }

  // Check for hidden elements that might be capturing data
  const hiddenElementResults = checkForHiddenElements()
  if (hiddenElementResults.suspicious) {
    results.suspicious = true
    results.reasons.push(...hiddenElementResults.reasons)
    results.confidence = "high"
  }

  // If suspicious content is found, report to background script
  if (results.suspicious) {
    chrome.runtime.sendMessage({
      action: "contentScanResults",
      url: window.location.href,
      results,
    })

    // If confidence is high, show warning immediately
    if (results.confidence === "high") {
      // Request background script to show warning
      chrome.runtime.sendMessage({
        action: "showContentWarning",
        url: window.location.href,
        reasons: results.reasons,
      })
    }
  }
}

// Function to check for suspicious login forms
function checkForLoginForms() {
  const result = {
    suspicious: false,
    reasons: [],
  }

  // Find all forms on the page
  const forms = document.querySelectorAll("form")

  forms.forEach((form) => {
    // Check if form has password field
    const hasPasswordField = form.querySelector('input[type="password"]') !== null

    if (hasPasswordField) {
      // Check if form submits to a different domain
      const formAction = form.getAttribute("action")

      if (formAction) {
        try {
          const formActionUrl = new URL(formAction, window.location.href)
          if (formActionUrl.hostname !== window.location.hostname) {
            result.suspicious = true
            result.reasons.push("Login form submits data to a different domain")
          }
        } catch (error) {
          console.error("Error parsing form action URL:", error)
        }
      }

      // Check for excessive hidden fields in login forms (often used in phishing)
      const hiddenFields = form.querySelectorAll('input[type="hidden"]')
      if (hiddenFields.length > 5) {
        result.suspicious = true
        result.reasons.push("Login form contains an unusual number of hidden fields")
      }

      // Check if the form asks for unusual information for a login
      const inputFields = form.querySelectorAll('input:not([type="hidden"]):not([type="submit"]):not([type="button"])')
      let unusualFields = 0

      inputFields.forEach((field) => {
        const fieldName = field.name.toLowerCase()
        const fieldId = field.id.toLowerCase()
        const fieldType = field.type.toLowerCase()

        // Check for unusual fields in login forms
        const unusualFieldPatterns = [
          "ssn",
          "social",
          "tax",
          "national",
          "identity",
          "id-number",
          "passport",
          "credit",
          "card",
          "cvv",
          "cvc",
          "pin",
          "mother",
          "maiden",
          "birth",
        ]

        if (unusualFieldPatterns.some((pattern) => fieldName.includes(pattern) || fieldId.includes(pattern))) {
          unusualFields++
        }
      })

      if (unusualFields > 0) {
        result.suspicious = true
        result.reasons.push("Login form requests sensitive information not typically required for login")
      }
    }
  })

  return result
}

// Function to check for brand impersonation
function checkForBrandImpersonation() {
  const result = {
    suspicious: false,
    reasons: [],
  }

  // List of commonly impersonated brands and their official domains
  const brands = {
    paypal: ["paypal.com", "paypal.me"],
    apple: ["apple.com", "icloud.com"],
    microsoft: ["microsoft.com", "live.com", "office.com", "outlook.com"],
    google: ["google.com", "gmail.com"],
    facebook: ["facebook.com", "fb.com"],
    amazon: ["amazon.com", "amazon.co.uk"],
    netflix: ["netflix.com"],
    gtbank: ["gtbank.com"],
    zenithbank: ["zenithbank.com"],
    accessbank: ["accessbankplc.com"],
  }

  // Check for brand logos in the page
  const images = document.querySelectorAll("img")

  for (const brand in brands) {
    // Check if brand name appears in page title
    if (document.title.toLowerCase().includes(brand)) {
      // Check if we're on the official domain for this brand
      const currentHostname = window.location.hostname
      const isOfficialDomain = brands[brand].some(
        (domain) => currentHostname === domain || currentHostname.endsWith("." + domain),
      )

      if (!isOfficialDomain) {
        result.suspicious = true
        result.reasons.push(`Page title contains "${brand}" but is not hosted on an official ${brand} domain`)
      }
    }

    // Check for brand name in image alt text or src
    let brandImageCount = 0
    images.forEach((img) => {
      const altText = (img.alt || "").toLowerCase()
      const imgSrc = (img.src || "").toLowerCase()

      if (altText.includes(brand) || imgSrc.includes(brand)) {
        brandImageCount++
      }
    })

    if (brandImageCount > 0) {
      // Check if we're on the official domain for this brand
      const currentHostname = window.location.hostname
      const isOfficialDomain = brands[brand].some(
        (domain) => currentHostname === domain || currentHostname.endsWith("." + domain),
      )

      if (!isOfficialDomain) {
        result.suspicious = true
        result.reasons.push(`Page contains ${brand} images but is not hosted on an official ${brand} domain`)
      }
    }
  }

  return result
}

// Function to check for SSL/TLS issues
function checkForSSLIssues() {
  const result = {
    suspicious: false,
    reasons: [],
  }

  // Check if the page is loaded over HTTPS
  if (window.location.protocol !== "https:") {
    // If the page contains login forms but is not using HTTPS, that's suspicious
    const hasLoginForm = document.querySelector('input[type="password"]') !== null

    if (hasLoginForm) {
      result.suspicious = true
      result.reasons.push("Page contains login form but does not use secure HTTPS connection")
    }
  }

  // Check for mixed content (HTTP resources on HTTPS page)
  if (window.location.protocol === "https:") {
    const insecureElements = []

    // Check for insecure images
    document.querySelectorAll('img[src^="http:"]').forEach((img) => {
      insecureElements.push(img)
    })

    // Check for insecure scripts
    document.querySelectorAll('script[src^="http:"]').forEach((script) => {
      insecureElements.push(script)
    })

    // Check for insecure stylesheets
    document.querySelectorAll('link[rel="stylesheet"][href^="http:"]').forEach((link) => {
      insecureElements.push(link)
    })

    if (insecureElements.length > 0) {
      result.suspicious = true
      result.reasons.push("Page contains mixed content (insecure HTTP resources on HTTPS page)")
    }
  }

  return result
}

// Function to check for suspicious redirects
function checkForSuspiciousRedirects() {
  const result = {
    suspicious: false,
    reasons: [],
  }

  // Check for JavaScript redirects
  const scripts = document.querySelectorAll("script")

  scripts.forEach((script) => {
    const scriptContent = script.textContent || ""

    // Check for common redirect patterns
    const redirectPatterns = [
      "window.location",
      "document.location",
      "location.href",
      "location.replace",
      "location.assign",
    ]

    for (const pattern of redirectPatterns) {
      if (scriptContent.includes(pattern)) {
        // This is a potential redirect, check if it's going to a different domain
        const matches = scriptContent.match(new RegExp(`${pattern}\\s*=\\s*["']([^"']+)["']`))

        if (matches && matches[1]) {
          try {
            const redirectUrl = new URL(matches[1], window.location.href)

            if (redirectUrl.hostname !== window.location.hostname) {
              result.suspicious = true
              result.reasons.push("Page contains script that redirects to a different domain")
            }
          } catch (error) {
            console.error("Error parsing redirect URL:", error)
          }
        }
      }
    }
  })

  // Check for meta refresh redirects
  const metaRefresh = document.querySelector('meta[http-equiv="refresh"]')

  if (metaRefresh) {
    const content = metaRefresh.getAttribute("content") || ""
    const urlMatch = content.match(/url=([^;]+)/i)

    if (urlMatch && urlMatch[1]) {
      try {
        const redirectUrl = new URL(urlMatch[1], window.location.href)

        if (redirectUrl.hostname !== window.location.hostname) {
          result.suspicious = true
          result.reasons.push("Page uses meta refresh to redirect to a different domain")
        }
      } catch (error) {
        console.error("Error parsing meta refresh URL:", error)
      }
    }
  }

  return result
}

// Function to check for hidden elements that might be capturing data
function checkForHiddenElements() {
  const result = {
    suspicious: false,
    reasons: [],
  }

  // Check for invisible forms
  const forms = document.querySelectorAll("form")

  forms.forEach((form) => {
    const style = window.getComputedStyle(form)

    // Check if the form is hidden but still functional
    if (
      style.display === "none" ||
      style.visibility === "hidden" ||
      style.opacity === "0" ||
      Number.parseInt(style.opacity) === 0
    ) {
      // Check if the hidden form contains input fields
      const inputFields = form.querySelectorAll("input")

      if (inputFields.length > 0) {
        result.suspicious = true
        result.reasons.push("Page contains hidden form that may be capturing data")
      }
    }
  })

  // Check for transparent overlays that might be capturing clicks
  const divs = document.querySelectorAll("div")

  divs.forEach((div) => {
    const style = window.getComputedStyle(div)

    // Check for elements that cover a large portion of the page but are invisible
    if (style.position === "absolute" || style.position === "fixed") {
      const width = Number.parseInt(style.width)
      const height = Number.parseInt(style.height)

      if (width > window.innerWidth * 0.5 && height > window.innerHeight * 0.5) {
        // Check if the element is invisible
        if (style.opacity === "0" || Number.parseInt(style.opacity) === 0 || style.backgroundColor === "transparent") {
          result.suspicious = true
          result.reasons.push("Page contains large invisible overlay that may be capturing clicks")
        }
      }
    }
  })

  return result
}

// Listen for messages from the background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "showWarning") {
    // Create and show warning overlay
    showWarningOverlay(message.url, message.reasons)
    sendResponse({ success: true })
  }

  if (message.action === "hideWarning") {
    // Remove warning overlay
    const overlay = document.getElementById("phishguard-warning-overlay")
    if (overlay) {
      overlay.remove()
    }
    sendResponse({ success: true })
  }
})

// Function to show warning overlay on the page
function showWarningOverlay(url, reasons) {
  // Remove any existing overlay
  const existingOverlay = document.getElementById("phishguard-warning-overlay")
  if (existingOverlay) {
    existingOverlay.remove()
  }

  // Create overlay container
  const overlay = document.createElement("div")
  overlay.id = "phishguard-warning-overlay"
  overlay.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background-color: rgba(255, 0, 0, 0.9);
    z-index: 2147483647;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    font-family: Arial, sans-serif;
    color: white;
    text-align: center;
    padding: 20px;
  `

  // Create warning content
  const content = document.createElement("div")
  content.style.cssText = `
    background-color: white;
    border-radius: 8px;
    padding: 20px;
    max-width: 600px;
    width: 80%;
    color: black;
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
  `

  // Add warning icon
  const icon = document.createElement("div")
  icon.innerHTML = "⚠️"
  icon.style.cssText = `
    font-size: 64px;
    margin-bottom: 20px;
  `
  content.appendChild(icon)

  // Add warning title
  const title = document.createElement("h1")
  title.textContent = "Phishing Warning"
  title.style.cssText = `
    color: red;
    margin: 0 0 20px 0;
    font-size: 24px;
  `
  content.appendChild(title)

  // Add warning message
  const message = document.createElement("p")
  message.textContent = `This website (${new URL(url).hostname}) has been detected as a potential phishing site.`
  message.style.cssText = `
    margin: 0 0 20px 0;
    font-size: 16px;
  `
  content.appendChild(message)

  // Add reasons list
  if (reasons && reasons.length > 0) {
    const reasonsTitle = document.createElement("p")
    reasonsTitle.textContent = "Reasons:"
    reasonsTitle.style.cssText = `
      font-weight: bold;
      margin: 0 0 10px 0;
    `
    content.appendChild(reasonsTitle)

    const reasonsList = document.createElement("ul")
    reasonsList.style.cssText = `
      text-align: left;
      margin: 0 0 20px 0;
      padding-left: 20px;
    `

    reasons.forEach((reason) => {
      const item = document.createElement("li")
      item.textContent = reason
      item.style.cssText = `
        margin-bottom: 5px;
      `
      reasonsList.appendChild(item)
    })

    content.appendChild(reasonsList)
  }

  // Add educational tip
  const tip = document.createElement("div")
  tip.style.cssText = `
    background-color: #f8f8f8;
    border-left: 4px solid #2196F3;
    padding: 10px;
    margin-bottom: 20px;
    text-align: left;
  `

  const tipTitle = document.createElement("p")
  tipTitle.textContent = "Security Tip:"
  tipTitle.style.cssText = `
    font-weight: bold;
    margin: 0 0 5px 0;
    color: #2196F3;
  `
  tip.appendChild(tipTitle)

  const tipText = document.createElement("p")
  tipText.textContent =
    "Always verify the website URL before entering sensitive information. Legitimate websites use secure connections (https://) and don't ask for unnecessary personal details."
  tipText.style.cssText = `
    margin: 0;
    font-size: 14px;
  `
  tip.appendChild(tipText)

  content.appendChild(tip)

  // Add buttons
  const buttons = document.createElement("div")
  buttons.style.cssText = `
    display: flex;
    justify-content: space-between;
  `

  // Back to safety button
  const backButton = document.createElement("button")
  backButton.textContent = "Back to Safety"
  backButton.style.cssText = `
    background-color: #4CAF50;
    border: none;
    color: white;
    padding: 10px 20px;
    text-align: center;
    text-decoration: none;
    display: inline-block;
    font-size: 16px;
    margin: 4px 2px;
    cursor: pointer;
    border-radius: 4px;
  `
  backButton.addEventListener("click", () => {
    window.history.back()
  })
  buttons.appendChild(backButton)

  // Proceed anyway button
  const proceedButton = document.createElement("button")
  proceedButton.textContent = "Proceed Anyway (Unsafe)"
  proceedButton.style.cssText = `
    background-color: #f44336;
    border: none;
    color: white;
    padding: 10px 20px;
    text-align: center;
    text-decoration: none;
    display: inline-block;
    font-size: 16px;
    margin: 4px 2px;
    cursor: pointer;
    border-radius: 4px;
  `
  proceedButton.addEventListener("click", () => {
    overlay.remove()

    // Inform background script that user proceeded anyway
    chrome.runtime.sendMessage({
      action: "userProceededAnyway",
      url,
    })
  })
  buttons.appendChild(proceedButton)

  content.appendChild(buttons)
  overlay.appendChild(content)

  // Add overlay to page
  document.body.appendChild(overlay)
}

