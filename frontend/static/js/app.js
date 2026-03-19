// VulnBank — Shared Auth Helpers
// VULN: JWT-1 — JWT stored in localStorage, accessible to any JS on the page
// VULN: JWT-2 — payload decoded client-side; subscription_type fully visible

const API = '';

function getToken() {
    return localStorage.getItem('jwt_token');
}

function getPayload() {
    const t = getToken();
    if (!t) return null;
    try {
        // VULN: JWT-1 — payload decoded client-side without verification
        const b64 = t.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
        return JSON.parse(atob(b64));
    } catch (e) { return null; }
}

function authHeaders() {
    return {
        'Authorization': 'Bearer ' + getToken(),
        'Content-Type':  'application/json',
    };
}

function requireAuth() {
    if (!getToken()) {
        window.location.href = '/index.html';
    }
}

function logout() {
    localStorage.clear();
    document.cookie = 'jwt_token=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/';
    window.location.href = '/index.html';
}

function showAlert(elementId, message, type = 'error') {
    const el = document.getElementById(elementId);
    if (!el) return;
    el.className = `alert alert-${type}`;
    el.textContent = message;
    el.style.display = 'flex';
}

function hideAlert(elementId) {
    const el = document.getElementById(elementId);
    if (el) el.style.display = 'none';
}

function formatCurrency(amount) {
    return new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(amount);
}

function formatDate(dateStr) {
    if (!dateStr) return 'N/A';
    return new Date(dateStr).toLocaleDateString('en-US', {
        year: 'numeric', month: 'short', day: 'numeric'
    });
}

function getSubscriptionBadge(tier) {
    const tiers = {
        gold:   { class: 'badge-gold',   label: 'Gold' },
        silver: { class: 'badge-silver', label: 'Silver' },
        bronze: { class: 'badge-bronze', label: 'Bronze' },
    };
    const t = tiers[tier] || tiers['bronze'];
    return `<span class="badge ${t.class}">${t.label}</span>`;
}

// Set navbar user info on pages that have a navbar
document.addEventListener('DOMContentLoaded', function () {
    const payload = getPayload();
    const userEl = document.getElementById('nav-user');
    if (userEl && payload) {
        // VULN: JWT-1 — subscription_type visible from client-decoded JWT
        userEl.textContent = `${payload.username} · ${payload.subscription_type}`;
    }
});
