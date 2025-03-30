// PhishGuard - Report Page Script
// This script handles the phishing site report form

// Get DOM elements
const reportUrl = document.getElementById("report-url")
const categorySelect = document.getElementById("category")
const detailsTextarea = document.getElementById("details")
const emailInput = document.getElementById("email")
const submitBtn = document.getElementById("submit-btn")
const cancelBtn = document.getElementById("cancel-btn")
const closeBtn = document.getElementById("close-btn")
const reportForm = document.getElementById("report-form")
const thankYou = document.getElementById("thank-you")
const statusMessage = document.getElementById("status-message")

// Get URL from query parameters
document.addEventListener("DOMContentLoaded", () => {
  const urlParams = new URLSearchParams(window.location.search)
  const url = urlParams.get("url")

  if (url) {
    reportUrl.textContent = url
  } else {
    reportUrl.textContent = "No URL provided"
    submitBtn.disabled = true
  }
})

// Submit report
submitBtn.addEventListener("click", async () => {
  try {
    const url = reportUrl.textContent
    const category = categorySelect.value
    const details = detailsTextarea.value
    const email = emailInput.value

    if (!url || url === "No URL provided") {
      showStatus("No URL to report", "error")
      return
    }

    // Disable submit button while submitting
    submitBtn.disabled = true
    submitBtn.textContent = "Submitting..."

    // Send report to background script
    try {
      const response = await chrome.runtime.sendMessage({
        action: "reportPhishing",
        url,
        details: {
          category,
          details,
          reporterEmail: email,
        },
      })

      if (response && response.success) {
        // Show thank you message
        reportForm.style.display = "none"
        thankYou.style.display = "block"
      } else {
        showStatus("Error submitting report. Please try again.", "error")
        submitBtn.disabled = false
        submitBtn.textContent = "Submit Report"
      }
    } catch (sendMessageError) {
      console.error("Error sending message to background script:", sendMessageError)
      showStatus("Error submitting report. Please try again.", "error")
      submitBtn.disabled = false
      submitBtn.textContent = "Submit Report"
    }
  } catch (error) {
    console.error("Error submitting report:", error)
    showStatus("Error submitting report. Please try again.", "error")
    submitBtn.disabled = false
    submitBtn.textContent = "Submit Report"
  }
})

// Cancel report
cancelBtn.addEventListener("click", () => {
  window.close()
})

// Close thank you page
closeBtn.addEventListener("click", () => {
  window.close()
})

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

