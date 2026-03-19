// Exploitable Bank — Profile JS
document.addEventListener('DOMContentLoaded', async function () {
    requireAuth();
    await loadProfile();
});

async function loadProfile() {
    try {
        const resp = await fetch('/api/profile', { headers: authHeaders() });
        const user = await resp.json();

        document.getElementById('full_name').value        = user.full_name || '';
        document.getElementById('email').value            = user.email || '';
        document.getElementById('phone').value            = user.phone || '';
        document.getElementById('address').value          = user.address || '';
        document.getElementById('ssn-display').textContent = user.ssn || 'N/A';  // VULN: A02 — plaintext SSN

        // Set avatar
        if (user.avatar_url) {
            document.getElementById('avatar-img').src         = user.avatar_url;
            document.getElementById('avatar-object').data     = user.avatar_url;
            document.getElementById('avatar-url-link').href   = user.avatar_url;
            document.getElementById('avatar-url-link').textContent = user.avatar_url;
        }

        document.getElementById('sub-badge').innerHTML = getSubscriptionBadge(user.subscription_type);
    } catch (e) {
        showAlert('alert-box', 'Failed to load profile', 'error');
    }
}

document.getElementById('profile-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    hideAlert('alert-box');

    const payload = {
        full_name: document.getElementById('full_name').value.trim(),
        email:     document.getElementById('email').value.trim(),
        phone:     document.getElementById('phone').value.trim(),
        address:   document.getElementById('address').value.trim(),
    };

    const btn = document.getElementById('save-btn');
    btn.disabled = true;
    btn.innerHTML = '<span class="loading"></span> Saving...';

    try {
        const resp = await fetch('/api/profile/update', {
            method:  'POST',
            headers: authHeaders(),
            body:    JSON.stringify(payload),
        });

        const data = await resp.json();

        if (!resp.ok) {
            showAlert('alert-box', data.error || 'Update failed', 'error');
            return;
        }

        showAlert('alert-box', 'Profile updated successfully.', 'success');
        document.getElementById('sub-badge').innerHTML = getSubscriptionBadge(data.subscription_type);
    } catch (err) {
        showAlert('alert-box', 'Network error: ' + err.message, 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = 'Save Changes';
    }
});

document.getElementById('avatar-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    hideAlert('avatar-alert');

    const fileInput = document.getElementById('avatar-file');
    if (!fileInput.files.length) {
        showAlert('avatar-alert', 'Please select a file', 'error');
        return;
    }

    const formData = new FormData();
    formData.append('avatar', fileInput.files[0]);

    const btn = document.getElementById('upload-btn');
    btn.disabled = true;
    btn.textContent = 'Uploading...';

    try {
        const resp = await fetch('/api/profile/avatar', {
            method:  'POST',
            headers: { 'Authorization': 'Bearer ' + getToken() },
            body:    formData,
        });

        const data = await resp.json();

        if (!resp.ok) {
            showAlert('avatar-alert', data.error || 'Upload failed', 'error');
            return;
        }

        // VULN: VD-SVG — Set both img src and object data; object tag executes SVG scripts
        document.getElementById('avatar-img').src    = data.avatar_url;
        document.getElementById('avatar-object').data = data.avatar_url;
        document.getElementById('avatar-url-link').href = data.avatar_url;
        document.getElementById('avatar-url-link').textContent = data.avatar_url;

        showAlert('avatar-alert', 'Avatar updated successfully.', 'success');
    } catch (err) {
        showAlert('avatar-alert', 'Network error: ' + err.message, 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = 'Upload Avatar';
    }
});
