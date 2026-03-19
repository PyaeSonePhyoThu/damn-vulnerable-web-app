// VulnBank — Dashboard JS
document.addEventListener('DOMContentLoaded', async function () {
    requireAuth();

    const payload = getPayload();
    if (!payload) return logout();

    // Show user info from JWT (VULN: JWT-1 — subscription visible client-side)
    document.getElementById('welcome-name').textContent = payload.username || 'User';
    document.getElementById('sub-badge').innerHTML = getSubscriptionBadge(payload.subscription_type);

    await loadAccounts();
    await loadTransactions();
    await loadCards();
});

async function loadAccounts() {
    try {
        const resp = await fetch('/api/accounts', { headers: authHeaders() });
        const accounts = await resp.json();
        const container = document.getElementById('accounts-container');
        container.innerHTML = '';

        if (!accounts.length) {
            container.innerHTML = '<p style="color:var(--text-light);font-size:13px;">No accounts found.</p>';
            return;
        }

        let totalBalance = 0;
        accounts.forEach(acc => {
            totalBalance += acc.balance;
            container.innerHTML += `
            <div class="account-card">
              <div class="acc-type">${acc.account_type} Account</div>
              <div class="acc-number">${acc.account_number}</div>
              <div class="acc-balance">${formatCurrency(acc.balance)}</div>
              <div class="acc-currency">${acc.currency} · VulnBank</div>
            </div>`;
        });

        document.getElementById('total-balance').textContent = formatCurrency(totalBalance);
        document.getElementById('account-count').textContent = accounts.length;
    } catch (e) {
        document.getElementById('accounts-container').innerHTML =
            '<p style="color:var(--danger);">Failed to load accounts.</p>';
    }
}

async function loadTransactions() {
    try {
        const resp = await fetch('/api/transactions', { headers: authHeaders() });
        const txns = await resp.json();
        const tbody = document.getElementById('txn-tbody');
        tbody.innerHTML = '';

        if (!txns.length) {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-light);">No transactions yet</td></tr>';
            return;
        }

        txns.slice(0, 10).forEach(tx => {
            const payload = getPayload();
            const accs = [];
            tbody.innerHTML += `
            <tr>
              <td>${tx.created_at ? tx.created_at.slice(0, 10) : 'N/A'}</td>
              <td style="font-family:monospace;font-size:12px;">${tx.from_account}</td>
              <td style="font-family:monospace;font-size:12px;">${tx.to_account}</td>
              <td><strong>${formatCurrency(tx.amount)}</strong></td>
              <td><span class="badge badge-success">${tx.status || 'completed'}</span></td>
            </tr>`;
        });
    } catch (e) {
        document.getElementById('txn-tbody').innerHTML =
            '<tr><td colspan="5" style="color:var(--danger);">Failed to load transactions.</td></tr>';
    }
}

async function loadCards() {
    try {
        const resp = await fetch('/api/cards', { headers: authHeaders() });
        const cards = await resp.json();
        const container = document.getElementById('cards-container');
        container.innerHTML = '';

        if (!cards.length) {
            container.innerHTML = '<p style="color:var(--text-light);font-size:13px;">No cards found.</p>';
            return;
        }

        // VULN: A02 — Full card numbers and CVVs displayed in plaintext
        cards.forEach(card => {
            container.innerHTML += `
            <div style="background:linear-gradient(135deg,var(--navy-dark),var(--navy-light));color:white;border-radius:10px;padding:18px;margin-bottom:12px;">
              <div style="font-size:11px;letter-spacing:1.5px;color:var(--gold);margin-bottom:10px;text-transform:uppercase;">${card.card_type} Card</div>
              <div style="font-family:monospace;font-size:16px;letter-spacing:2px;margin-bottom:12px;">${card.card_number}</div>
              <div style="display:flex;justify-content:space-between;font-size:12px;color:rgba(255,255,255,0.7);">
                <span>${card.card_holder}</span>
                <span>Exp: ${card.expiry_date}</span>
                <span>CVV: <strong style="color:var(--gold);">${card.cvv}</strong></span>
              </div>
            </div>`;
        });
    } catch (e) { /* silently fail */ }
}

async function downloadStatement() {
    const btn = document.getElementById('pdf-btn');
    btn.disabled = true;
    btn.innerHTML = '<span class="loading"></span> Generating...';

    try {
        const resp = await fetch('/api/pdf/statement', {
            headers: { 'Authorization': 'Bearer ' + getToken() }
        });

        if (!resp.ok) {
            const data = await resp.json().catch(() => ({}));
            alert('PDF generation failed: ' + (data.error || resp.statusText) +
                  (data.detail ? '\n' + data.detail : ''));
            return;
        }

        const blob = await resp.blob();
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement('a');
        a.href     = url;
        a.download = resp.headers.get('Content-Disposition')?.match(/filename="(.+)"/)?.[1] || 'statement.pdf';
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
    } catch (err) {
        alert('Error: ' + err.message);
    } finally {
        btn.disabled = false;
        btn.textContent = '📄 Download Statement (PDF)';
    }
}
