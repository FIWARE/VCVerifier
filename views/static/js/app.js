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
    cfg.qrExpireAt = Date.now() + 30 * 1000
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
        const response = await fetch(`/static/locales/${lang}.json`);
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
    if (this.socket) this.socket.close();
  }

  #connectWebSocket(url) {
    this.socket = new WebSocket(url);
    this.socket.onopen = () => {
      console.log('WebSocket connected')
    }
    this.socket.onerror = (err) => {
      console.log(err)
    }

    this.socket.onclose = (e) => {
      if (e.code !== 1000) {
        console.log(e.code)
      }
    }
    this.socket.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data)

        switch (message.type) {
          case "session":
            console.log("Session initiated")
            break
          case "authenticated":
            console.log("Redirect initiated " + message.redirectUrl)
            window.location.href = message.redirectUrl;
            break

          case "error":
            console.log("error")
            socket.close()
            break
        }
      } catch (err) {
        console.log(err)
      }
    };
  }
}

new AppManager();