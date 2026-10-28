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

  set(key, value) {
    this.settings[key] = String(value);
  }
}

// Keeps what a reload of this tab needs to resume the login session the page started. Reloading
// renders a new session with a new QR code and secret; on a phone the OS often reloads the tab
// instead of resuming it when the user comes back from the wallet, and the wallet's answer then
// completes the old session, whose result only the old secret can collect. sessionStorage survives
// a reload but not the tab, and holds no more than the page itself does: the secret is in its
// markup as well. Storage may be unavailable (private mode, blocked site data), so every access is
// guarded and the page works without it - it just does not resume.
class LoginSessionStore {
  static #key = 'vcverifier.loginSession';

  // A different login - other client, state or scope - never resumes this one.
  static #request() {
    return window.location.pathname + window.location.search;
  }

  static load() {
    try {
      const stored = JSON.parse(window.sessionStorage.getItem(LoginSessionStore.#key));
      return stored && stored.request === LoginSessionStore.#request() ? stored.session : null;
    } catch (err) {
      return null;
    }
  }

  static save(session) {
    try {
      window.sessionStorage.setItem(LoginSessionStore.#key, JSON.stringify({ request: LoginSessionStore.#request(), session }));
    } catch (err) {
      console.log('Cannot keep the login session for a reload:', err);
    }
  }

  static clear() {
    try {
      window.sessionStorage.removeItem(LoginSessionStore.#key);
    } catch (err) {
      // nothing was stored either
    }
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
    // set once the QR code expired; the page then only waits for a login that completed while it
    // was away, until collectUntil (see #handleExpiration)
    this.expired = false;
    this.collectUntil = 0;
    this.collectTimer = null;
    this.hiddenAt = null;
    this.socketCreatedAt = 0;
    // the session the server rendered with this page, while the page waits on one from before a
    // reload (see #resumeStoredSession)
    this.freshSession = null;
    this.theme = new ThemeManager(this.config.get('defaultTheme'));

    this.#initTheme();
    this.#resumeStoredSession();
    this.#initEventListeners();
    // a resumed session whose QR code expired only collects (see #resumeStoredSession)
    if (!this.expired) this.#startTimer();
  }

  // What identifies the login session the page waits on, and what it shows for it.
  #renderedSession() {
    return {
      wsUrl: this.config.get('wsUrl'),
      wsSecret: this.config.get('wsSecret'),
      qrExpireAt: this.config.getInt('qrExpireAt'),
      qrDuration: this.config.getInt('qrDuration'),
      qrcode: document.querySelector('#qrcode img')?.getAttribute('src'),
      authRequest: document.querySelector('#openWallet a')?.getAttribute('href'),
    };
  }

  #applySession(session) {
    ['wsUrl', 'wsSecret', 'qrExpireAt', 'qrDuration'].forEach(key => this.config.set(key, session[key]));
    if (session.qrcode) document.querySelector('#qrcode img')?.setAttribute('src', session.qrcode);
    if (session.authRequest) document.querySelector('#openWallet a')?.setAttribute('href', session.authRequest);
  }

  // After a reload, waits on the session the page had before, while a result can still come from
  // it: the QR code is still valid, or a login completed while the page was away may still be kept
  // for it. The session the server just rendered stays unused unless the old one ends without a
  // result (#fallBackToFreshSession) - an unused session costs the server nothing but its lifetime.
  #resumeStoredSession() {
    const rendered = this.#renderedSession();
    const stored = LoginSessionStore.load();
    const collectUntil = stored ? stored.qrExpireAt + stored.qrDuration * 1000 : 0;
    if (!stored || stored.wsUrl === rendered.wsUrl || Date.now() >= collectUntil) {
      LoginSessionStore.save(rendered);
      return;
    }
    console.log('Resuming the login session from before the reload');
    this.freshSession = rendered;
    this.#applySession(stored);
    // Its QR code expired: nothing can be scanned any more, so the page only asks for a result -
    // showing the connecting notice, not the expired code - and falls back to the new session.
    if (Date.now() >= stored.qrExpireAt) this.expired = true;
  }

  // The session from before the reload ended without a result for this page: it expired, or the
  // server no longer knows it. The session rendered with the page takes over, without an error -
  // for the user this is simply the page they loaded. It reports whether there was one to take over.
  #fallBackToFreshSession() {
    const fresh = this.freshSession;
    if (!fresh) return false;
    this.freshSession = null;
    this.#finishWebSocket();
    clearInterval(this.timerInterval);
    // The rendered session started at the reload and has been running since. Taking over once the
    // old QR code expired, it has only as long left as the old one had run before the reload - a
    // reload 3s after the first load leaves 3s. Too little to scan: reload into a new session,
    // with nothing stored, so the reload does not resume either.
    if (fresh.qrExpireAt - Date.now() < fresh.qrDuration * 1000 / 2) {
      console.log('The login session from before the reload ended, and the new one is nearly expired: starting a new login session');
      LoginSessionStore.clear();
      window.location.reload();
      return true;
    }
    console.log('The login session from before the reload ended, continuing with a new one');
    this.#applySession(fresh);
    LoginSessionStore.save(fresh);

    this.expired = false;
    this.collectUntil = 0;
    this.socketEverConnected = false;
    this.reconnectAttempts = 0;
    document.getElementById('qrcode')?.classList.remove('blur-lg', 'grayscale', 'opacity-50');
    ['qrcode', 'timer-section', 'expired-overlay', 'presentation-rejected'].forEach(id => document.getElementById(id)?.classList.add('hidden'));
    ['ws-error', 'session-invalid', 'page-unauthorized', 'another-tab'].forEach(id => {
      document.getElementById(id)?.classList.add('hidden');
      document.getElementById(id)?.classList.remove('flex');
    });
    document.getElementById('ws-connecting')?.classList.remove('hidden');

    this.socketFinished = false;
    this.#startTimer();
    this.#connectWebSocket(fresh.wsUrl);
    return true;
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
      if (!wsUrl) return;
      if (this.expired) {
        this.#startCollecting();
      } else {
        this.#connectWebSocket(wsUrl);
      }
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
    // a page showing another panel - "another tab" - starts once the user continues here
    if (this.socketFinished) return;
    this.#startCollecting();
  }

  // A login that completed while the page was away - on a phone, the wallet app was in front - is
  // kept for the page as long as its code, which lives as long as a session and was issued before
  // the QR code expired. Keep asking for it until then; the expired notice stays meanwhile.
  #startCollecting() {
    this.collectUntil = this.config.getInt('qrExpireAt') + this.config.getInt('qrDuration') * 1000;
    clearTimeout(this.collectTimer);
    this.collectTimer = setTimeout(() => this.#stopCollecting(), Math.max(this.collectUntil - Date.now(), 0));
    clearTimeout(this.reconnectTimer);
    this.reconnectAttempts = 0;
    // Timers are throttled or suspended in the background, so this may run while the page is
    // hidden, where a connection fails anyway; the page asks once it is visible again.
    if (document.visibilityState === 'visible') this.#collectLogin();
  }

  // Gives up waiting for a login result after the QR code expired. The expired notice on the QR
  // code says so; a page that does not show the QR code - it continued from "another tab", or
  // never got connected - shows "session no longer valid" instead of the connecting notice.
  #stopCollecting() {
    if (this.#fallBackToFreshSession()) return;
    LoginSessionStore.clear();
    this.#finishWebSocket();
    if (document.getElementById('qrcode')?.classList.contains('hidden')) this.#showWebSocketError('session-invalid');
  }

  // Asks the server for a login that completed while the page was away, by connecting anew: the
  // server hands it only to a connection that presented the page secret.
  #collectLogin() {
    // a connection opened a moment ago - when the page became visible - already asks for it
    if (this.socket && this.socket.readyState === WebSocket.CONNECTING) return;
    if (this.socket && this.socket.readyState === WebSocket.OPEN && Date.now() - this.socketCreatedAt < 1000) return;
    this.#connectWebSocket(this.config.get('wsUrl'));
  }

  // Coming back to the page - typically from the wallet app on the same phone - reconnects at once:
  // the socket may have died in the background, and a login that completed meanwhile is handed to a
  // new connection. A short switch away keeps the socket, unless the QR code expired meanwhile.
  #handleVisibilityChange() {
    if (document.visibilityState === 'hidden') {
      this.hiddenAt = Date.now();
      return;
    }
    const hiddenFor = this.hiddenAt === null ? 0 : Date.now() - this.hiddenAt;
    this.hiddenAt = null;
    if (this.socketFinished) return;
    if (this.expired) {
      console.log(`Page visible again after ${hiddenFor}ms, asking for a login that completed meanwhile`);
      clearTimeout(this.reconnectTimer);
      this.reconnectAttempts = 0;
      this.#collectLogin();
      return;
    }
    // a reconnect already scheduled stays scheduled
    if (hiddenFor < 2000) return;
    console.log(`Page visible again after ${hiddenFor}ms, reconnecting`);
    clearTimeout(this.reconnectTimer);
    this.reconnectAttempts = 0;
    this.#connectWebSocket(this.config.get('wsUrl'));
  }

  // Stops using the socket for good: no reconnect after this.
  #finishWebSocket() {
    this.socketFinished = true;
    clearTimeout(this.reconnectTimer);
    clearTimeout(this.collectTimer);
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
    if (this.#fallBackToFreshSession()) return;
    LoginSessionStore.clear();
    this.#finishWebSocket();
    this.#showWebSocketError('session-invalid');
  }

  // The server did not accept this page's secret: a stale page, or a customised page that does not
  // send it. No reconnect can fix that.
  #handlePageUnauthorized(reason) {
    if (this.#fallBackToFreshSession()) return;
    console.error(`WebSocket rejected (${reason}): the page did not present a valid secret. A customised login page must send the wsSecret meta value as {"type":"auth","secret":...} on every connection.`);
    LoginSessionStore.clear();
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
    // after the QR code expired, only a login that completed meanwhile is left to collect
    if (this.expired) {
      this.#startCollecting();
      return;
    }
    this.reconnectAttempts = 0;
    this.#connectWebSocket(this.config.get('wsUrl'));
  }

  static #isHttpUrl(value) {
    try {
      const protocol = new URL(value).protocol;
      return protocol === 'http:' || protocol === 'https:';
    } catch {
      return false;
    }
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
    this.socketCreatedAt = Date.now();
    // The server replaces it with the new connection anyway; closing it first keeps it quiet. A
    // closed socket delivers no more messages, so a login result the server wrote to it is lost -
    // the server keeps the result pending and hands it to the new connection.
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
      // After the QR code expired only a rejection is final: 4403 means nothing is pending (any more)
      // and 4409 that another tab took over. A dropped connection - the page may still be in the
      // background - is retried while a pending login can exist; the expired notice stays.
      if (this.expired) {
        if (e.code === 4409) {
          console.log('The login continues in another tab after the QR code expired');
          this.#handleReplaced();
          return;
        }
        if (e.code === 4403 || Date.now() >= this.collectUntil) {
          console.log(`No login result after the QR code expired (code ${e.code})`);
          this.#stopCollecting();
          return;
        }
        const delay = AppManager.#reconnectDelay(this.reconnectAttempts);
        this.reconnectAttempts++;
        console.log(`WebSocket closed (code ${e.code}) after the QR code expired, asking again in ${delay}ms`);
        this.reconnectTimer = setTimeout(() => this.#connectWebSocket(url), delay);
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
      if (socket !== this.socket) return;
      try {
        const message = JSON.parse(event.data)

        // After the QR code expired the page only waits for a login result. "session" is no answer:
        // the server's session may outlive the QR code on this page's clock, and a login completing
        // then still arrives on this connection. The close event decides about the others.
        if (this.expired && message.type !== "authenticated") {
          console.log(`Waiting for a login result after the QR code expired (${message.type})`);
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
            // going back to this page later starts a new login
            LoginSessionStore.clear();
            this.#finishWebSocket();
            // the server only accepts http(s) redirect URIs; never navigate to anything else, a
            // "javascript:" URL would run in the verifier's origin
            if (!AppManager.#isHttpUrl(message.redirectUrl)) {
              console.error("Refusing to redirect to a non-http(s) URL: " + message.redirectUrl);
              this.#showWebSocketError();
              break
            }
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