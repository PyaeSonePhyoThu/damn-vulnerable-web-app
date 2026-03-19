// Exploitable Bank — Transfer JS
document.addEventListener('DOMContentLoaded', async function () {
    requireAuth();
    await loadAccounts();

    const payload = getPayload();
    if (payload) {
        const sub = payload.subscription_type || 'bronze';
        const limits = { bronze: 1000, silver: 5000, gold: 50000 };
        const daily  = { bronze: 3000, silver: 15000, gold: 100000 };
        document.getElementById('limit-info').innerHTML =
            `Subscription: ${getSubscriptionBadge(sub)} &nbsp;·&nbsp; ` +
            `Transfer limit: <strong>${formatCurrency(limits[sub] || 1000)}</strong> &nbsp;·&nbsp; ` +
            `Daily limit: <strong>${formatCurrency(daily[sub] || 3000)}</strong>`;
    }
});

async function loadAccounts() {
    const resp = await fetch('/api/accounts', { headers: authHeaders() });
    const accounts = await resp.json();
    const select = document.getElementById('from_account');
    select.innerHTML = '<option value="">— Select account —</option>';
    accounts.forEach(acc => {
        select.innerHTML += `<option value="${acc.account_number}">${acc.account_number} (${acc.account_type}) — ${formatCurrency(acc.balance)}</option>`;
    });
}

document.getElementById('transfer-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    hideAlert('alert-box');

    const from_account = document.getElementById('from_account').value;
    const to_account   = document.getElementById('to_account').value.trim();
    const amount       = parseFloat(document.getElementById('amount').value);
    const feeRaw       = document.getElementById('fee').value;
    const description  = document.getElementById('description').value.trim() || 'Transfer';
    const btn          = document.getElementById('transfer-btn');

    btn.disabled = true;
    btn.innerHTML = '<span class="loading"></span> Processing...';

    try {
        const body = { from_account, to_account, amount, description };
        if (feeRaw !== '') body.fee = parseFloat(feeRaw);

        const resp = await fetch('/api/transfer', {
            method:  'POST',
            headers: authHeaders(),
            body:    JSON.stringify(body),
        });

        const data = await resp.json();

        if (!resp.ok) {
            showAlert('alert-box', data.error || 'Transfer failed', 'error');
            return;
        }

        showAlert('alert-box',
            `Transfer of ${formatCurrency(data.amount)} completed! Fee: ${formatCurrency(data.fee)}. New balance: ${formatCurrency(data.new_balance)}`,
            'success');
        await loadAccounts();
        document.getElementById('transfer-form').reset();
    } catch (err) {
        showAlert('alert-box', 'Network error: ' + err.message, 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = 'Send Transfer';
    }
});
