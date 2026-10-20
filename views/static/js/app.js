class ThemeManager {
  #defaultColor

  constructor(defaultColor) {
    this.#defaultColor = defaultColor || '#2563eb';
    this.#applyDynamicColors();
  }

  /**
   * Reads 'primaryColor' from URL and updates the CSS variable.
   * Example: ?primaryColor=ff5733 (omit the # for cleaner URLs)
   */
  #applyDynamicColors() {
    const params = new URLSearchParams(window.location.search);
    const customColor = params.get('primaryColor');
    let hexColor = this.#defaultColor;
    if (customColor) {
      hexColor = customColor.startsWith('#') ? customColor : `#${customColor}`;
      const isValidHex = /^#([A-Fa-f0-9]{3}){1,2}$|^#([A-Fa-f0-9]{4}){1,2}$/.test(hexColor);
      if (!isValidHex) {
        hexColor = this.#defaultColor;
      }
    }

    document.documentElement.style.setProperty('--color-primary', hexColor);
    console.log(`Theme: Primary color updated to ${hexColor}`);
  }
}

class ConfigManager {
  constructor() {
    this.settings = this.#parseMetaConfig();
  }

  #parseMetaConfig() {
    const cfg = {};
    document.querySelectorAll('meta[name]').forEach(meta => {
      cfg[meta.getAttribute('name')] = meta.getAttribute('content');
    });
    return cfg;
  }

  get(key, defaultValue = null) {
    return this.settings[key] !== undefined ? this.settings[key] : defaultValue;
  }

  getInt(key, defaultValue = 0) {
    const val = parseInt(this.get(key));
    return isNaN(val) ? defaultValue : val;
  }
}

class LocaleManager {
  constructor() {
    this.cache = new Map();
    this.translations = {};
  }

  async setLanguage(lang) {
    try {
      if (!this.cache.has(lang)) {
        const basePath = document.querySelector('meta[name="basePath"]')?.getAttribute('content') || '';
        const response = await fetch(`${basePath}/static/locales/${lang}.json`);
        const data = await response.json();
        this.cache.set(lang, data);
      }
      this.translations = this.cache.get(lang);
      this.#updateDOM();
      localStorage.setItem('lang', lang);
    } catch (err) {
      console.error("Locale Error:", err);
    }
  }

  #updateDOM() {
    document.querySelectorAll('[data-i18n]').forEach(el => {
      const key = el.getAttribute('data-i18n');
      const text = key.split('.').reduce((obj, i) => (obj ? obj[i] : null), this.translations);
      if (text) el.innerText = text;
    });
  }
}

class AppManager {
  constructor() {
    this.config = new ConfigManager();
    this.i18n = new LocaleManager();
    this.socket = null;
    // set once the page is done with the socket (redirected, expired or failed), so a closing
    // socket is not reconnected
    this.socketFinished = false;
    this.socketEverConnected = false;
    this.reconnectAttempts = 0;
    this.reconnectTimer = null;
    this.theme = new ThemeManager(this.config.get('defaultTheme'));

    this.#initTheme();
    this.#initEventListeners();
    this.#startTimer();
  }

  #initTheme() {
    const isDark = localStorage.getItem('color-theme') === 'dark' ||
      (!('color-theme' in localStorage) && window.matchMedia('(prefers-color-scheme: dark)').matches);

    document.documentElement.classList.toggle('dark', isDark);
    document.getElementById('theme-toggle-dark-icon')?.classList.toggle('hidden', isDark);
    document.getElementById('theme-toggle-light-icon')?.classList.toggle('hidden', !isDark);

    document.getElementById('theme-toggle')?.addEventListener('click', () => {
      const isNowDark = document.documentElement.classList.toggle('dark');
      document.getElementById('theme-toggle-dark-icon')?.classList.toggle('hidden');
      document.getElementById('theme-toggle-light-icon')?.classList.toggle('hidden');
      localStorage.setItem('color-theme', isNowDark ? 'dark' : 'light');
    });
  }

  #initEventListeners() {
    const langSelector = document.getElementById('lang-selector');
    const savedLang = localStorage.getItem('lang') || 'en';
    if (langSelector) {
      langSelector.value = savedLang;
      this.i18n.setLanguage(savedLang);
      langSelector.addEventListener('change', (e) => this.i18n.setLanguage(e.target.value));
    }

    window.addEventListener('load', () => {
      const wsUrl = this.config.get('wsUrl');
      if (wsUrl) this.#connectWebSocket(wsUrl);
    });

    document.addEventListener("DOMContentLoaded", function () {
      const isMobile = /Android|iPhone|iPad|iPod/i.test(navigator.userAgent);
      const walletButtonContainer = document.querySelector('#openWallet');

      if (isMobile) {
        walletButtonContainer.classList.remove('hidden');
      }
    });
  }

  #startTimer() {
    const expireAt = this.config.getInt('qrExpireAt');
    const duration = this.config.getInt('qrDuration');

    const progressBar = document.getElementById('progress-bar');
    const timerText = document.getElementById('timer-text');

    if (this.timerInterval) clearInterval(this.timerInterval);

    const update = () => {
      const nowMs = Date.now();
      const timeLeftMs = expireAt - nowMs;
      const timeLeftSec = Math.ceil(timeLeftMs / 1000);

      if (timerText) {
        timerText.innerText = `${Math.max(timeLeftSec, 0)}s`;
      }

      if (progressBar) {
        const percentage = (timeLeftMs / (duration * 1000)) * 100;
        const safePercentage = Math.min(Math.max(percentage, 0), 100);
        progressBar.style.width = `${safePercentage}%`;
      }

      // Must match animation duration
      if (timeLeftMs <= -100) {
        clearInterval(this.timerInterval);
        this.#handleExpiration();
      }
    };

    update();
    this.timerInterval = setInterval(update, 100);
  }

  #handleExpiration() {
    document.getElementById('qrcode')?.classList.add('blur-lg', 'grayscale', 'opacity-50');
    document.getElementById('expired-overlay')?.classList.remove('hidden');
    this.#finishWebSocket();
  }

  // Stops using the socket for good: no reconnect after this.
  #finishWebSocket() {
    this.socketFinished = true;
    clearTimeout(this.reconnectTimer);
    if (this.socket) this.socket.close(1000);
  }

  // Replaces the QR code with one of the error panels: 'ws-error' (cannot connect) or
  // 'session-invalid' (the login session expired or was already used).
  #showWebSocketError(panelId = 'ws-error') {
    document.getElementById('ws-connecting')?.classList.add('hidden');
    document.getElementById('qrcode')?.classList.add('hidden');
    document.getElementById('timer-section')?.classList.add('hidden');
    const panel = document.getElementById(panelId);
    if (panel) {
      panel.classList.remove('hidden');
      panel.classList.add('flex');
    }
  }

  #handleSessionInvalid() {
    this.#finishWebSocket();
    this.#showWebSocketError('session-invalid');
  }

  // Delay before the given reconnect attempt: 1s, 2s, 4s, 8s, then 10s.
  static #reconnectDelay(attempt) {
    return Math.min(1000 * 2 ** attempt, 10000);
  }

  #connectWebSocket(url) {
    // The socket can drop while the QR is shown (a proxy closing it, a network change). The login
    // only completes over it, so reconnect to the same session until the QR expires; the server
    // replaces the old connection. A page that never got connected gives up sooner, since the
    // QR is not shown before the first connection.
    const socket = new WebSocket(url);
    this.socket = socket;

    socket.onopen = () => {
      console.log('WebSocket connected');
      this.socketEverConnected = true;
      this.reconnectAttempts = 0;
      document.getElementById('ws-connecting')?.classList.add('hidden');
      document.getElementById('qrcode')?.classList.remove('hidden');
      document.getElementById('timer-section')?.classList.remove('hidden');
    }
    socket.onerror = (err) => {
      // always followed by onclose, which decides whether to reconnect
      console.error('WebSocket error:', err);
    }

    socket.onclose = (e) => {
      if (this.socketFinished || socket !== this.socket) return;
      // the server closes with 4403 when the session no longer exists; no reconnect can succeed
      if (e.code === 4403) {
        this.#handleSessionInvalid();
        return;
      }
      const maxReconnectAttempts = this.socketEverConnected ? 6 : 2;
      if (this.reconnectAttempts >= maxReconnectAttempts) {
        console.error(`WebSocket closed (code ${e.code}), giving up after ${this.reconnectAttempts} reconnect attempts`);
        this.socketFinished = true;
        this.#showWebSocketError();
        return;
      }
      const delay = AppManager.#reconnectDelay(this.reconnectAttempts);
      this.reconnectAttempts++;
      console.log(`WebSocket closed (code ${e.code}), reconnecting in ${delay}ms`);
      this.reconnectTimer = setTimeout(() => this.#connectWebSocket(url), delay);
    }
    socket.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data)

        switch (message.type) {
          case "session":
            console.log("Session initiated")
            break
          case "authenticated":
            console.log("Redirect initiated " + message.redirectUrl)
            this.#finishWebSocket();
            window.location.href = message.redirectUrl;
            break

          case "error":
            console.log("Session error: " + message.reason)
            this.#handleSessionInvalid();
            break
        }
      } catch (err) {
        console.log(err)
      }
    };
  }
}

new AppManager();