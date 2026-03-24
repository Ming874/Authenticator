/**
 * Secure Authenticator - Core Logic
 * WebAuthn (Biometrics) | AES-GCM | IndexedDB | TOTP
 */

const App = {
    state: {
        isLocked: true,
        accounts: [],
        masterKey: null,
        db: null,
        credentialId: localStorage.getItem('auth_credential_id'),
        touchStart: 0,
        activeSwipedCard: null
    },

    async init() {
        this.registerServiceWorker();
        await this.initDB();
        this.bindEvents();
        this.startTimer();
    },

    registerServiceWorker() {
        if ('serviceWorker' in navigator) {
            navigator.serviceWorker.register('./sw.js').catch(err => console.error('SW failed:', err));
            let refreshing = false;
            navigator.serviceWorker.addEventListener('controllerchange', () => {
                if (!refreshing) { refreshing = true; window.location.reload(); }
            });
        }
    },

    initDB() {
        return new Promise((resolve) => {
            const request = indexedDB.open("AuthenticatorDB", 1);
            request.onupgradeneeded = (e) => {
                const db = e.target.result;
                if (!db.objectStoreNames.contains("vault")) db.createObjectStore("vault", { keyPath: "id" });
            };
            request.onsuccess = (e) => { this.state.db = e.target.result; resolve(); };
        });
    },

    bindEvents() {
        document.getElementById('unlock-btn').addEventListener('click', () => this.handleUnlock());
        document.getElementById('add-manual-btn').addEventListener('click', () => {
            document.getElementById('manual-overlay').classList.remove('hidden');
        });
        document.getElementById('cancel-manual').addEventListener('click', () => this.closeManualModal());
        document.getElementById('save-manual').addEventListener('click', () => this.saveManualAccount());
        document.getElementById('cancel-edit').addEventListener('click', () => this.closeEditModal());
        document.getElementById('save-edit').addEventListener('click', () => this.saveEdit());

        // Global click to reset swiped cards
        document.addEventListener('touchstart', (e) => {
            if (this.state.activeSwipedCard && !e.target.closest('.otp-card-wrapper')) {
                this.state.activeSwipedCard.classList.remove('swiped');
                this.state.activeSwipedCard = null;
            }
        }, { passive: true });
    },

    // --- Auth Logic ---
    async handleUnlock() {
        try {
            if (!this.state.credentialId) await this.registerDevice();
            else await this.verifyDevice();
            await this.unlockVault();
        } catch (err) { alert("Authentication failed"); }
    },

    async registerDevice() {
        const challenge = window.crypto.getRandomValues(new Uint8Array(32));
        const userID = window.crypto.getRandomValues(new Uint8Array(16));
        const publicKey = {
            challenge,
            rp: { name: "Secure Authenticator" },
            user: { id: userID, name: "user@local", displayName: "Local User" },
            pubKeyCredParams: [{ alg: -7, type: "public-key" }, { alg: -257, type: "public-key" }],
            authenticatorSelection: { authenticatorAttachment: "platform", userVerification: "required" },
            timeout: 60000
        };
        const credential = await navigator.credentials.create({ publicKey });
        const idBase64 = btoa(String.fromCharCode(...new Uint8Array(credential.rawId)));
        localStorage.setItem('auth_credential_id', idBase64);
        this.state.credentialId = idBase64;
    },

    async verifyDevice() {
        const challenge = window.crypto.getRandomValues(new Uint8Array(32));
        const rawId = Uint8Array.from(atob(this.state.credentialId), c => c.charCodeAt(0));
        const publicKey = { challenge, allowCredentials: [{ id: rawId, type: 'public-key' }], userVerification: "required", timeout: 60000 };
        await navigator.credentials.get({ publicKey });
    },

    // --- Vault & Encryption ---
    async getMasterKey() {
        if (this.state.masterKey) return this.state.masterKey;
        const enc = new TextEncoder();
        const baseKey = await window.crypto.subtle.importKey("raw", enc.encode("user-session-entropy-v2"), "PBKDF2", false, ["deriveKey"]);
        this.state.masterKey = await window.crypto.subtle.deriveKey(
            { name: "PBKDF2", salt: enc.encode("secure-salt-v2"), iterations: 100000, hash: "SHA-256" },
            baseKey, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
        );
        return this.state.masterKey;
    },

    async encrypt(text) {
        const key = await this.getMasterKey();
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encrypted = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(text));
        return { encrypted, iv };
    },

    async decrypt(encrypted, iv) {
        const key = await this.getMasterKey();
        const decrypted = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, encrypted);
        return new TextDecoder().decode(decrypted);
    },

    async unlockVault() {
        const tx = this.state.db.transaction("vault", "readonly");
        const request = tx.objectStore("vault").getAll();
        request.onsuccess = async () => {
            const results = [];
            for (const item of request.result) {
                try {
                    const secret = await this.decrypt(item.encrypted, item.iv);
                    results.push({ id: item.id, label: item.label, secret });
                } catch (e) {}
            }
            this.state.accounts = results;
            this.state.isLocked = false;
            document.getElementById('auth-screen').classList.add('hidden');
            document.getElementById('main-screen').classList.remove('hidden');
            this.renderList();
        };
    },

    async saveAccount(label, secret) {
        const { encrypted, iv } = await this.encrypt(secret);
        const entry = { id: Date.now(), label, encrypted, iv };
        const tx = this.state.db.transaction("vault", "readwrite");
        tx.objectStore("vault").add(entry);
        tx.oncomplete = () => {
            if (!this.state.isLocked) { this.state.accounts.push({ id: entry.id, label, secret }); this.renderList(); }
        };
    },

    saveManualAccount() {
        const label = document.getElementById('manual-label').value.trim();
        const secret = document.getElementById('manual-secret').value.trim().replace(/\s/g, '').toUpperCase();
        if (!label || !secret || !/^[A-Z2-7]+=*$/.test(secret)) { alert("Invalid input"); return; }
        this.saveAccount(label, secret);
        this.closeManualModal();
    },

    // --- Swipe & Edit ---
    async renderList() {
        const container = document.getElementById('otp-list');
        container.innerHTML = '';

        if (this.state.accounts.length > 0) {
            const hint = document.createElement('div');
            hint.className = 'swipe-hint';
            hint.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M15 18l-6-6 6-6"/></svg> Swipe left to edit`;
            container.appendChild(hint);
        }

        for (const acc of this.state.accounts) {
            const code = await this.generateTOTP(acc.secret);
            const wrapper = document.createElement('div');
            wrapper.className = 'otp-card-wrapper';
            
            wrapper.innerHTML = `
                <div class="otp-card-action">Edit</div>
                <div class="otp-card" id="card-${acc.id}">
                    <div class="otp-label">${acc.label}</div>
                    <div class="otp-code">${code.substring(0,3)} ${code.substring(3)}</div>
                    <div class="progress-track"><div class="progress-fill"></div></div>
                </div>
            `;

            const card = wrapper.querySelector('.otp-card');
            const action = wrapper.querySelector('.otp-card-action');
            
            // Edit Button Click
            action.onclick = () => {
                this.openEditModal(acc.id, acc.label);
                card.classList.remove('swiped');
                this.state.activeSwipedCard = null;
            };

            // Swipe Logic
            card.addEventListener('touchstart', (e) => {
                this.state.touchStart = e.touches[0].clientX;
            }, { passive: true });

            card.addEventListener('touchend', (e) => {
                const touchEnd = e.changedTouches[0].clientX;
                const diff = this.state.touchStart - touchEnd;

                if (diff > 40) { // Swipe left
                    if (this.state.activeSwipedCard) this.state.activeSwipedCard.classList.remove('swiped');
                    card.classList.add('swiped');
                    this.state.activeSwipedCard = card;
                } else if (diff < -40) { // Swipe right
                    card.classList.remove('swiped');
                    this.state.activeSwipedCard = null;
                } else if (Math.abs(diff) < 10) { // Click
                    if (card.classList.contains('swiped')) {
                        card.classList.remove('swiped');
                        this.state.activeSwipedCard = null;
                    } else {
                        navigator.clipboard.writeText(code);
                        this.showToast("Copied to clipboard");
                    }
                }
            });

            container.appendChild(wrapper);
        }
        this.updateProgressBar(); // 初始渲染後立即更新一次進度條
    },

    openEditModal(id, currentLabel) {
        document.getElementById('edit-id').value = id;
        document.getElementById('edit-label').value = currentLabel;
        document.getElementById('edit-overlay').classList.remove('hidden');
    },

    closeEditModal() { document.getElementById('edit-overlay').classList.add('hidden'); },

    async saveEdit() {
        const id = parseInt(document.getElementById('edit-id').value);
        const newLabel = document.getElementById('edit-label').value.trim();
        if (!newLabel) return;
        const tx = this.state.db.transaction("vault", "readwrite");
        const store = tx.objectStore("vault");
        const request = store.get(id);
        request.onsuccess = () => {
            const data = request.result;
            if (data) {
                data.label = newLabel;
                store.put(data);
                tx.oncomplete = () => {
                    const acc = this.state.accounts.find(a => a.id === id);
                    if (acc) acc.label = newLabel;
                    this.renderList();
                    this.showToast("Account updated");
                    this.closeEditModal();
                };
            }
        };
    },

    // --- TOTP Utils ---
    base32ToBuf(s) {
        const a = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let b = "", r = [];
        for (let i=0; i<s.length; i++) {
            let v = a.indexOf(s[i].toUpperCase());
            if (v===-1) continue;
            b += v.toString(2).padStart(5, '0');
        }
        for (let i=0; i+8<=b.length; i+=8) r.push(parseInt(b.substring(i, i+8), 2));
        return new Uint8Array(r);
    },

    async generateTOTP(secret) {
        const key = await window.crypto.subtle.importKey("raw", this.base32ToBuf(secret), {name:"HMAC", hash:{name:"SHA-1"}}, false, ["sign"]);
        const t = Math.floor(Math.floor(Date.now()/1000)/30);
        const b = new ArrayBuffer(8);
        new DataView(b).setUint32(4, t);
        const h = new Uint8Array(await window.crypto.subtle.sign("HMAC", key, b));
        const o = h[h.length-1] & 0xf;
        const c = ((h[o]&0x7f)<<24)|((h[o+1]&0xff)<<16)|((h[o+2]&0xff)<<8)|(h[o+3]&0xff);
        return (c%1000000).toString().padStart(6, '0');
    },

    showToast(m) {
        const t = document.createElement('div');
        t.className = "toast"; t.innerText = m;
        document.body.appendChild(t);
        setTimeout(() => t.remove(), 2000);
    },

    closeManualModal() { 
        document.getElementById('manual-overlay').classList.add('hidden'); 
        document.getElementById('manual-label').value = '';
        document.getElementById('manual-secret').value = '';
    },

    updateProgressBar() {
        const p = (30 - (new Date().getSeconds() % 30)) / 30;
        document.querySelectorAll('.progress-fill').forEach(el => el.style.transform = `scaleX(${p})`);
    },

    startTimer() {
        setInterval(() => {
            if (!this.state.isLocked) {
                this.updateProgressBar();
                if (new Date().getSeconds() % 30 === 0) this.renderList();
            }
        }, 200);
    }
};

App.init();
