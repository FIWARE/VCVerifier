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
    // set once the QR code expired; the page then only asks once more for a login that completed
    // while it was away
    this.expired = false;
    this.hiddenAt = null;
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

    document.getElementById('continue-here')?.addEventListener('click', () => this.#continueHere());
    document.addEventListener('visibilitychange', () => this.#handleVisibilityChange());

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
    this.expired = true;
    if (this.socketFinished) return;
    // A login that completed while the page was away - on a phone, the wallet app was in front - is
    // kept for the page beyond the QR code's lifetime. Ask for it once more; the server answers with
    // the result, or closes the connection.
    clearTimeout(this.reconnectTimer);
    this.#connectWebSocket(this.config.get('wsUrl'));
  }

  // Coming back to the page - typically from the wallet app on the same phone - reconnects at once:
  // the socket may have died in the background, and the server hands a login that completed
  // meanwhile only to a new connection. A short switch away keeps the socket.
  #handleVisibilityChange() {
    if (document.visibilityState === 'hidden') {
      this.hiddenAt = Date.now();
      return;
    }
    const hiddenFor = this.hiddenAt === null ? 0 : Date.now() - this.hiddenAt;
    this.hiddenAt = null;
    if (this.socketFinished || this.expired || hiddenFor < 2000) return;
    console.log(`Page visible again after ${hiddenFor}ms, reconnecting`);
    clearTimeout(this.reconnectTimer);
    this.reconnectAttempts = 0;
    this.#connectWebSocket(this.config.get('wsUrl'));
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
    document.getElementById('presentation-rejected')?.classList.add('hidden');
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

  // The server did not accept this page's secret: a stale page, or a customised page that does not
  // send it. No reconnect can fix that.
  #handlePageUnauthorized(reason) {
    console.error(`WebSocket rejected (${reason}): the page did not present a valid secret. A customised login page must send the wsSecret meta value as {"type":"auth","secret":...} on every connection.`);
    this.#finishWebSocket();
    this.#showWebSocketError('page-unauthorized');
  }

  // The page was opened in another tab as well, and the newer tab took the login over. Reconnecting
  // on its own would take it back and the two tabs would keep replacing each other, so this one
  // waits until the user asks to continue here.
  #handleReplaced() {
    this.#finishWebSocket();
    this.#showWebSocketError('another-tab');
  }

  // A presentation for this login was rejected. The session stays open and the QR code valid, so
  // the user can try again; anyone who saw the QR can cause this, so it is only a notice.
  #showRejection(reason) {
    const notice = document.getElementById('presentation-rejected');
    if (!notice) return;
    const details = notice.querySelectorAll('[data-rejection]');
    const known = Array.from(details).some(el => el.getAttribute('data-rejection') === reason);
    details.forEach(el => el.classList.toggle('hidden', el.getAttribute('data-rejection') !== (known ? reason : 'verification_failed')));
    notice.classList.remove('hidden');
  }

  #continueHere() {
    const panel = document.getElementById('another-tab');
    panel?.classList.add('hidden');
    panel?.classList.remove('flex');
    document.getElementById('ws-connecting')?.classList.remove('hidden');
    this.socketFinished = false;
    this.reconnectAttempts = 0;
    this.#connectWebSocket(this.config.get('wsUrl'));
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
    const previous = this.socket;
    const socket = new WebSocket(url);
    this.socket = socket;
    // the server replaces it with the new connection anyway; closing it first keeps it quiet
    if (previous && previous.readyState <= WebSocket.OPEN) previous.close(1000);

    // Every connection first presents the page's secret: the session id is in the QR, so only the
    // secret shows that this is the page that started the login. The server registers the
    // connection, and answers with "session", only once it checked it.
    socket.onopen = () => {
      console.log('WebSocket connected');
      socket.send(JSON.stringify({ type: 'auth', secret: this.config.get('wsSecret', '') }));
    }
    socket.onerror = (err) => {
      // always followed by onclose, which decides whether to reconnect
      console.error('WebSocket error:', err);
    }

    socket.onclose = (e) => {
      if (this.socketFinished || socket !== this.socket) return;
      // the last attempt after the QR code expired got no result: the expired notice stays
      if (this.expired) {
        this.#finishWebSocket();
        return;
      }
      // the server closes with 4403 when the session no longer exists or the page could not
      // authenticate; no reconnect can succeed
      if (e.code === 4403) {
        this.#handleSessionInvalid();
        return;
      }
      // 4409: a newer connection of this page, in another tab, took over
      if (e.code === 4409) {
        this.#handleReplaced();
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

        // A socket this page replaced may still bring what the server sent before it was closed.
        // Only the login result counts: the server hands it out once, so it is not sent again.
        if (socket !== this.socket && message.type !== "authenticated") return;

        // the last attempt after the QR code expired only waits for a login result
        if (this.expired && message.type !== "authenticated") {
          console.log(`No login result after the QR code expired (${message.type})`);
          this.#finishWebSocket();
          return;
        }

        switch (message.type) {
          case "session":
            console.log("Session initiated")
            this.socketEverConnected = true;
            this.reconnectAttempts = 0;
            document.getElementById('ws-connecting')?.classList.add('hidden');
            document.getElementById('qrcode')?.classList.remove('hidden');
            document.getElementById('timer-section')?.classList.remove('hidden');
            break
          case "authenticated":
            console.log("Redirect initiated " + message.redirectUrl)
            this.#finishWebSocket();
            window.location.href = message.redirectUrl;
            break

          case "error":
            // the close event (4403) follows; #finishWebSocket makes it a no-op
            if (message.reason === 'session_not_found') {
              console.log("Session error: " + message.reason)
              this.#handleSessionInvalid();
            } else {
              this.#handlePageUnauthorized(message.reason);
            }
            break

          case "replaced":
            console.log("The login continues in another tab")
            this.#handleReplaced();
            break

          case "rejected":
            console.log("A presentation was rejected: " + message.reason)
            this.#showRejection(message.reason);
            break
        }
      } catch (err) {
        console.log(err)
      }
    };
  }
}

new AppManager();