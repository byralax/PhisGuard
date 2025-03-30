# PhishGuard - Chrome Extension for Phishing Detection

## 🚀 Overview
PhishGuard is a Chrome extension built to protect users from phishing attacks by detecting and warning them about potentially malicious websites **in real-time**. It leverages multiple phishing databases, content analysis, and user feedback to provide **comprehensive protection** while respecting user privacy.

---

## 📂 Code Structure

### 🛡️ Background Script (`background.js`)
Handles URL checking against phishing databases and manages user settings.
- Uses the **Google Safe Browsing API** to verify URLs.
- Stores **no** browsing history or personal data.
- Requires a **valid API key** before deployment.

### 🔍 Content Script (`content.js`)
Analyzes webpage content for phishing indicators.
- Detects login forms that submit data to **different domains** (a common phishing tactic).
- Sends suspicious results to the background script for further evaluation.

### 🖥️ Popup UI (`popup.html` & `popup.js`)
Provides users with real-time safety status of the current site.
- Users can **scan the page** or **report a site**.
- Fetches the **current tab's URL** and checks it against phishing databases.

### ⚙️ Options Page (`options.html` & `options.js`)
Allows users to configure extension settings.
- Enable/disable specific security checks.
- Enter API keys for enhanced protection.
- Loads & updates settings dynamically from storage.

### 🚨 Report Page (`report.html` & `report.js`)
Allows users to report suspicious sites.
- Collects user input and submits reports to the background script.
- Helps improve phishing detection over time.

---

## 🔔 Important Notes!
✅ **API Keys:** Not included in the repository for security reasons. You must add a valid key before launching.
✅ **Privacy:** PhishGuard **does not** store browsing history or personal information.
✅ **Enhancements:** Future updates will include **machine learning integration**, **advanced content analysis**, **user feedback loops**, and **localization support**.

---

## 📞 Contact & Collaboration
💌 Email: **byralax@gmail.com**  
🌐 GitHub: [byralax](https://github.com/byralax)  

Let's work together to make the internet **safer for everyone**! 🛡️✨  

**Best regards,**  
**Iie Byron**  

