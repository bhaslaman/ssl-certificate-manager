/**
 * SSL Certificate Manager - Main JavaScript
 */

// ==================== THEME MANAGEMENT ====================

function initTheme() {
    const savedTheme = localStorage.getItem('theme') || 'light';
    setTheme(savedTheme);
}

function setTheme(theme) {
    document.documentElement.setAttribute('data-bs-theme', theme);
    localStorage.setItem('theme', theme);
    updateThemeIcon(theme);
}

function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-bs-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    setTheme(newTheme);
}

function updateThemeIcon(theme) {
    const icon = document.getElementById('theme-icon');
    if (icon) {
        icon.className = theme === 'dark' ? 'bi bi-sun-fill' : 'bi bi-moon-fill';
    }
}

// Initialize theme on page load
document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    checkForUpdates();
    highlightActiveNav();
});

// ==================== NAVIGATION ====================

function highlightActiveNav() {
    const path = window.location.pathname;
    const navLinks = document.querySelectorAll('.nav-tab-link');

    navLinks.forEach(link => {
        const href = link.getAttribute('href');
        const linkPath = href.split('?')[0]; // Remove query params

        if (path === linkPath || (path === '/' && linkPath === '/')) {
            link.classList.add('active');
        } else {
            link.classList.remove('active');
        }
    });
}

// ==================== UPDATE CHECK ====================

async function checkForUpdates() {
    try {
        const response = await fetch('/api/system/update-check');
        const data = await response.json();

        if (data.update_available && data.latest_version && data.release_url) {
            const badge = document.getElementById('update-badge');
            const versionSpan = document.getElementById('update-version');
            if (badge && versionSpan) {
                versionSpan.textContent = 'v' + data.latest_version;
                badge.dataset.url = data.release_url;
                badge.classList.remove('d-none');
            }
        }
    } catch (err) {
        // Silently fail - update check is not critical
        console.debug('Update check failed:', err);
    }
}

// ==================== UTILITIES ====================

// Toast notification helper
function showToast(message, type = 'success') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast align-items-center text-white bg-${type === 'success' ? 'success' : 'danger'} border-0`;
    toast.setAttribute('role', 'alert');
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">
                <i class="bi bi-${type === 'success' ? 'check-circle' : 'exclamation-circle'}"></i>
                ${message}
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
        </div>
    `;
    container.appendChild(toast);
    const bsToast = new bootstrap.Toast(toast);
    bsToast.show();
    toast.addEventListener('hidden.bs.toast', () => toast.remove());
}

// Copy to clipboard
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showToast(window.T.common.copy_success);
    });
}

// Download file helper
function downloadFile(content, filename, mimeType = 'text/plain') {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// Download binary file from response
function downloadBinaryResponse(response, filename) {
    response.blob().then(blob => {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    });
}

// Initialize drop zones
function initDropZones() {
    document.querySelectorAll('.drop-zone').forEach(zone => {
        const inputId = zone.dataset.input;
        const input = document.getElementById(inputId);
        const fileNameEl = zone.parentElement.querySelector('.file-name');
        const browseBtn = zone.querySelector('.browse-btn');

        // Click to browse
        browseBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            input.click();
        });

        zone.addEventListener('click', () => input.click());

        // Drag events
        zone.addEventListener('dragover', (e) => {
            e.preventDefault();
            zone.classList.add('dragover');
        });

        zone.addEventListener('dragleave', () => {
            zone.classList.remove('dragover');
        });

        zone.addEventListener('drop', (e) => {
            e.preventDefault();
            zone.classList.remove('dragover');
            if (e.dataTransfer.files.length) {
                input.files = e.dataTransfer.files;
                updateFileName(zone, fileNameEl, e.dataTransfer.files[0].name);
            }
        });

        // File input change
        input.addEventListener('change', () => {
            if (input.files.length) {
                updateFileName(zone, fileNameEl, input.files[0].name);
            }
        });
    });
}

function updateFileName(zone, fileNameEl, name) {
    zone.classList.add('has-file');
    if (fileNameEl) {
        fileNameEl.textContent = name;
    }
}

// ==================== CONVERT PAGE ====================

function initConvertPage() {
    initDropZones();

    let currentType = 'pfx_to_pem';

    // Type selection
    document.querySelectorAll('.conversion-type').forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            document.querySelectorAll('.conversion-type').forEach(i => i.classList.remove('active'));
            item.classList.add('active');

            currentType = item.dataset.type;
            document.getElementById('form-title').textContent = item.textContent.trim();

            // Show/hide form sections
            document.querySelectorAll('.convert-form-section').forEach(section => {
                section.classList.add('d-none');
            });
            document.getElementById(`form-${currentType}`).classList.remove('d-none');

            // Hide result
            document.getElementById('convert-result').classList.add('d-none');
        });
    });

    // Form submit
    document.getElementById('convert-form').addEventListener('submit', async (e) => {
        e.preventDefault();

        const formData = new FormData();
        let endpoint = '';

        switch (currentType) {
            case 'pfx_to_pem':
                endpoint = '/api/convert/pfx-to-pem';
                formData.append('file', document.getElementById('pfx-file').files[0]);
                formData.append('password', document.getElementById('pfx-password').value);
                formData.append('key_format', document.querySelector('input[name="pfx-key-format"]:checked').value);
                // Check if split export is enabled
                if (document.getElementById('pfx-split-export').checked) {
                    formData.append('export_mode', 'split');
                }
                break;
            case 'pem_to_pfx':
                endpoint = '/api/convert/pem-to-pfx';
                formData.append('cert_file', document.getElementById('pem-cert-file').files[0]);
                formData.append('key_file', document.getElementById('pem-key-file').files[0]);
                if (document.getElementById('pem-chain-file').files[0]) {
                    formData.append('chain_file', document.getElementById('pem-chain-file').files[0]);
                }
                formData.append('password', document.getElementById('pfx-out-password').value);
                formData.append('friendly_name', document.getElementById('friendly-name').value);
                break;
            case 'pem_to_der':
                endpoint = '/api/convert/pem-to-der';
                formData.append('file', document.getElementById('pem-to-der-file').files[0]);
                break;
            case 'der_to_pem':
                endpoint = '/api/convert/der-to-pem';
                formData.append('file', document.getElementById('der-to-pem-file').files[0]);
                break;
            case 'pem_to_p7b':
                endpoint = '/api/convert/pem-to-p7b';
                formData.append('cert_file', document.getElementById('pem-to-p7b-file').files[0]);
                if (document.getElementById('pem-to-p7b-chain-file').files[0]) {
                    formData.append('chain_file', document.getElementById('pem-to-p7b-chain-file').files[0]);
                }
                break;
            case 'p7b_to_pem':
                endpoint = '/api/convert/p7b-to-pem';
                formData.append('file', document.getElementById('p7b-to-pem-file').files[0]);
                break;
            case 'extract_key':
                endpoint = '/api/convert/extract-key';
                formData.append('file', document.getElementById('extract-key-file').files[0]);
                formData.append('password', document.getElementById('extract-key-password').value);
                formData.append('new_password', document.getElementById('extract-key-new-password').value);
                formData.append('key_format', document.querySelector('input[name="extract-key-format"]:checked').value);
                break;
            case 'extract_cert':
                endpoint = '/api/convert/extract-cert';
                formData.append('file', document.getElementById('extract-cert-file').files[0]);
                formData.append('password', document.getElementById('extract-cert-password').value);
                break;

            // JKS conversions
            case 'pfx_to_jks':
                endpoint = '/api/convert/pfx-to-jks';
                formData.append('file', document.getElementById('pfx-to-jks-file').files[0]);
                formData.append('pfx_password', document.getElementById('pfx-to-jks-pfx-password').value);
                formData.append('jks_password', document.getElementById('pfx-to-jks-jks-password').value);
                formData.append('alias', document.getElementById('pfx-to-jks-alias').value);
                break;
            case 'jks_to_pfx':
                endpoint = '/api/convert/jks-to-pfx';
                formData.append('file', document.getElementById('jks-to-pfx-file').files[0]);
                formData.append('jks_password', document.getElementById('jks-to-pfx-jks-password').value);
                formData.append('pfx_password', document.getElementById('jks-to-pfx-pfx-password').value);
                formData.append('alias', document.getElementById('jks-to-pfx-alias').value);
                break;
            case 'pem_to_jks':
                endpoint = '/api/convert/pem-to-jks';
                formData.append('cert_file', document.getElementById('pem-to-jks-cert-file').files[0]);
                formData.append('key_file', document.getElementById('pem-to-jks-key-file').files[0]);
                if (document.getElementById('pem-to-jks-chain-file').files[0]) {
                    formData.append('chain_file', document.getElementById('pem-to-jks-chain-file').files[0]);
                }
                formData.append('jks_password', document.getElementById('pem-to-jks-password').value);
                formData.append('alias', document.getElementById('pem-to-jks-alias').value);
                break;
        }

        try {
            const response = await fetch(endpoint, {
                method: 'POST',
                body: formData
            });

            // Check if split export is enabled for PFX to PEM
            const isSplitExport = currentType === 'pfx_to_pem' &&
                document.getElementById('pfx-split-export')?.checked;

            // Binary response (PFX, DER, P7B, JKS, or split ZIP)
            if (['pem_to_pfx', 'pem_to_der', 'pem_to_p7b', 'pfx_to_jks', 'jks_to_pfx', 'pem_to_jks'].includes(currentType) || isSplitExport) {
                if (response.ok) {
                    const filename = response.headers.get('content-disposition')?.match(/filename="(.+)"/)?.[1] || 'output';
                    downloadBinaryResponse(response, filename);
                    showToast(window.T.common.success);
                } else {
                    const error = await response.json();
                    showToast(error.detail, 'error');
                }
                return;
            }

            const data = await response.json();

            if (response.ok) {
                displayConvertResult(currentType, data);
                showToast(window.T.common.success);
            } else {
                showToast(data.detail, 'error');
            }
        } catch (err) {
            showToast(err.message, 'error');
        }
    });
}

function displayConvertResult(type, data) {
    const resultDiv = document.getElementById('convert-result');
    const contentDiv = document.getElementById('result-content');
    resultDiv.classList.remove('d-none');

    let html = '';

    if (data.certificate) {
        html += `
            <div class="result-item">
                <div class="result-label">${window.T.convert.certificate}</div>
                <pre class="pem-output">${escapeHtml(data.certificate)}</pre>
                <div class="action-buttons">
                    <button class="btn btn-outline-primary btn-sm" onclick="copyToClipboard(\`${escapeJs(data.certificate)}\`)">
                        <i class="bi bi-clipboard"></i> ${window.T.convert.copy}
                    </button>
                    <button class="btn btn-primary btn-sm" onclick="downloadFile(\`${escapeJs(data.certificate)}\`, '${data.filename || 'certificate'}.pem')">
                        <i class="bi bi-download"></i> ${window.T.convert.download}
                    </button>
                </div>
            </div>
        `;
    }

    if (data.private_key) {
        html += `
            <div class="result-item">
                <div class="result-label">${window.T.convert.private_key}</div>
                <pre class="pem-output">${escapeHtml(data.private_key)}</pre>
                <div class="action-buttons">
                    <button class="btn btn-outline-primary btn-sm" onclick="copyToClipboard(\`${escapeJs(data.private_key)}\`)">
                        <i class="bi bi-clipboard"></i> ${window.T.convert.copy}
                    </button>
                    <button class="btn btn-primary btn-sm" onclick="downloadFile(\`${escapeJs(data.private_key)}\`, '${data.filename || 'private_key'}.key')">
                        <i class="bi bi-download"></i> ${window.T.convert.download}
                    </button>
                </div>
            </div>
        `;
    }

    if (data.chain) {
        html += `
            <div class="result-item">
                <div class="result-label">${window.T.convert.chain}</div>
                <pre class="pem-output">${escapeHtml(data.chain)}</pre>
                <div class="action-buttons">
                    <button class="btn btn-outline-primary btn-sm" onclick="copyToClipboard(\`${escapeJs(data.chain)}\`)">
                        <i class="bi bi-clipboard"></i> ${window.T.convert.copy}
                    </button>
                    <button class="btn btn-primary btn-sm" onclick="downloadFile(\`${escapeJs(data.chain)}\`, '${data.filename || 'chain'}-chain.pem')">
                        <i class="bi bi-download"></i> ${window.T.convert.download}
                    </button>
                </div>
            </div>
        `;
    }

    if (data.certificates) {
        html += `
            <div class="result-item">
                <div class="result-label">${window.T.convert.certificate}</div>
                <pre class="pem-output">${escapeHtml(data.certificates)}</pre>
                <div class="action-buttons">
                    <button class="btn btn-outline-primary btn-sm" onclick="copyToClipboard(\`${escapeJs(data.certificates)}\`)">
                        <i class="bi bi-clipboard"></i> ${window.T.convert.copy}
                    </button>
                    <button class="btn btn-primary btn-sm" onclick="downloadFile(\`${escapeJs(data.certificates)}\`, '${data.filename || 'certificates'}.pem')">
                        <i class="bi bi-download"></i> ${window.T.convert.download}
                    </button>
                </div>
            </div>
        `;
    }

    contentDiv.innerHTML = html;
}

// ==================== ANALYZE PAGE ====================

function initAnalyzePage() {
    initDropZones();

    // File upload form
    document.getElementById('analyze-file-form').addEventListener('submit', async (e) => {
        e.preventDefault();

        const formData = new FormData();
        formData.append('file', document.getElementById('analyze-file').files[0]);
        formData.append('password', document.getElementById('analyze-password').value);

        try {
            const response = await fetch('/api/analyze/certificate', {
                method: 'POST',
                body: formData
            });

            const data = await response.json();

            if (response.ok) {
                displayAnalyzeResult(data.info);
            } else {
                showToast(data.detail, 'error');
            }
        } catch (err) {
            showToast(err.message, 'error');
        }
    });

    // Text paste form
    document.getElementById('analyze-text-form').addEventListener('submit', async (e) => {
        e.preventDefault();

        const pemText = document.getElementById('pem-text').value;
        const isCsr = pemText.includes('CERTIFICATE REQUEST');

        const formData = new FormData();

        let endpoint = '/api/analyze/certificate-text';
        if (isCsr) {
            endpoint = '/api/analyze/csr-text';
            formData.append('csr', pemText);
        } else {
            formData.append('certificate', pemText);
        }

        try {
            const response = await fetch(endpoint, {
                method: 'POST',
                body: formData
            });

            const data = await response.json();

            if (response.ok) {
                displayAnalyzeResult(data.info, isCsr);
            } else {
                showToast(data.detail, 'error');
            }
        } catch (err) {
            showToast(err.message, 'error');
        }
    });
}

function displayAnalyzeResult(info, isCsr = false) {
    document.getElementById('analyze-placeholder').classList.add('d-none');
    const resultDiv = document.getElementById('analyze-result');
    const contentDiv = document.getElementById('result-content');
    resultDiv.classList.remove('d-none');

    const t = window.T.analyze.result;
    let html = '';

    // Subject
    html += `
        <div class="cert-info-section">
            <h6><i class="bi bi-person"></i> ${t.subject}</h6>
            <table class="cert-info-table">
                ${Object.entries(info.subject).map(([k, v]) => `<tr><td>${k}</td><td>${escapeHtml(v)}</td></tr>`).join('')}
            </table>
        </div>
    `;

    // Issuer (not for CSR)
    if (!isCsr && info.issuer) {
        html += `
            <div class="cert-info-section">
                <h6><i class="bi bi-building"></i> ${t.issuer}</h6>
                <table class="cert-info-table">
                    ${Object.entries(info.issuer).map(([k, v]) => `<tr><td>${k}</td><td>${escapeHtml(v)}</td></tr>`).join('')}
                </table>
            </div>
        `;
    }

    // Validity (not for CSR)
    if (!isCsr && info.validity) {
        const isValid = info.validity.is_valid;
        const daysRemaining = info.validity.days_remaining;

        let statusBadge = `<span class="badge badge-valid">${t.valid}</span>`;
        if (!isValid) {
            statusBadge = `<span class="badge badge-expired">${t.expired}</span>`;
        } else if (daysRemaining < 30) {
            statusBadge = `<span class="badge badge-warning">${daysRemaining} ${t.days_remaining}</span>`;
        }

        html += `
            <div class="cert-info-section">
                <h6><i class="bi bi-calendar"></i> ${t.validity} ${statusBadge}</h6>
                <table class="cert-info-table">
                    <tr><td>${t.not_before}</td><td>${info.validity.not_before}</td></tr>
                    <tr><td>${t.not_after}</td><td>${info.validity.not_after}</td></tr>
                    <tr><td>${t.days_remaining}</td><td>${daysRemaining}</td></tr>
                </table>
            </div>
        `;
    }

    // Serial Number
    if (info.serial_number) {
        html += `
            <div class="cert-info-section">
                <h6><i class="bi bi-hash"></i> ${t.serial}</h6>
                <div class="fingerprint">${info.serial_number}</div>
            </div>
        `;
    }

    // Fingerprints
    if (info.fingerprints) {
        html += `
            <div class="cert-info-section">
                <h6><i class="bi bi-fingerprint"></i> ${t.fingerprints}</h6>
                <table class="cert-info-table">
                    <tr><td>SHA-256</td><td class="fingerprint">${info.fingerprints.sha256}</td></tr>
                    <tr><td>SHA-1</td><td class="fingerprint">${info.fingerprints.sha1}</td></tr>
                    <tr><td>MD5</td><td class="fingerprint">${info.fingerprints.md5}</td></tr>
                </table>
            </div>
        `;
    }

    // Public Key
    if (info.public_key) {
        html += `
            <div class="cert-info-section">
                <h6><i class="bi bi-key"></i> ${t.public_key}</h6>
                <table class="cert-info-table">
                    <tr><td>${t.algorithm}</td><td>${info.public_key.algorithm}</td></tr>
                    ${info.public_key.key_size ? `<tr><td>${t.key_size}</td><td>${info.public_key.key_size} bit</td></tr>` : ''}
                </table>
            </div>
        `;
    }

    // SAN
    if (info.extensions?.subject_alternative_names?.length) {
        html += `
            <div class="cert-info-section">
                <h6><i class="bi bi-globe"></i> ${t.san}</h6>
                <ul class="san-list">
                    ${info.extensions.subject_alternative_names.map(san =>
                        `<li><span class="badge bg-secondary">${san.type}</span>${escapeHtml(san.value)}</li>`
                    ).join('')}
                </ul>
            </div>
        `;
    }

    // Key Usage
    if (info.extensions?.key_usage?.usages?.length) {
        html += `
            <div class="cert-info-section">
                <h6><i class="bi bi-shield-check"></i> ${t.key_usage}</h6>
                <div class="key-usage-badges">
                    ${info.extensions.key_usage.usages.map(u => `<span class="badge bg-info">${u}</span>`).join('')}
                </div>
            </div>
        `;
    }

    // Extended Key Usage
    if (info.extensions?.extended_key_usage?.usages?.length) {
        html += `
            <div class="cert-info-section">
                <h6><i class="bi bi-shield-plus"></i> ${t.extended_key_usage}</h6>
                <div class="key-usage-badges">
                    ${info.extensions.extended_key_usage.usages.map(u => `<span class="badge bg-secondary">${u}</span>`).join('')}
                </div>
            </div>
        `;
    }

    // CA / Self-signed flags
    if (!isCsr) {
        html += `
            <div class="cert-info-section">
                <h6><i class="bi bi-info-circle"></i> ${window.LANG === 'tr' ? 'Diger Bilgiler' : 'Other Information'}</h6>
                <table class="cert-info-table">
                    <tr><td>${t.is_ca}</td><td>${info.extensions?.basic_constraints?.ca ? t.valid : '-'}</td></tr>
                    <tr><td>${t.self_signed}</td><td>${info.is_self_signed ? window.T.common.yes : window.T.common.no}</td></tr>
                </table>
            </div>
        `;
    }

    contentDiv.innerHTML = html;
}

// ==================== GENERATE PAGE ====================

function initGeneratePage() {
    initDropZones();

    let currentType = 'private_key';

    // Function to manage required attributes based on active section
    function updateRequiredFields(activeType) {
        // Remove required from all sections first
        document.querySelectorAll('.generate-form-section input[data-required="true"]').forEach(input => {
            input.removeAttribute('required');
        });

        // Add required back to active section
        const activeSection = document.getElementById(`form-${activeType}`);
        if (activeSection) {
            activeSection.querySelectorAll('input[data-required="true"]').forEach(input => {
                input.setAttribute('required', 'required');
            });
        }
    }

    // Mark initially required fields and setup
    document.querySelectorAll('.generate-form-section input[required]').forEach(input => {
        input.setAttribute('data-required', 'true');
    });

    // Initialize - remove required from hidden sections
    updateRequiredFields(currentType);

    // Type selection
    document.querySelectorAll('.generate-type').forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            document.querySelectorAll('.generate-type').forEach(i => i.classList.remove('active'));
            item.classList.add('active');

            currentType = item.dataset.type;
            document.getElementById('form-title').textContent = item.textContent.trim();

            // Show/hide form sections
            document.querySelectorAll('.generate-form-section').forEach(section => {
                section.classList.add('d-none');
            });
            document.getElementById(`form-${currentType}`).classList.remove('d-none');

            // Update required fields for the new active section
            updateRequiredFields(currentType);

            // Hide result
            document.getElementById('generate-result').classList.add('d-none');
        });
    });

    // Form submit
    document.getElementById('generate-form').addEventListener('submit', async (e) => {
        e.preventDefault();

        const formData = new FormData();
        let endpoint = '';

        switch (currentType) {
            case 'private_key':
                endpoint = '/api/generate/private-key';
                formData.append('key_type', document.getElementById('key-type').value);
                formData.append('password', document.getElementById('key-password').value);
                break;

            case 'key_and_cert':
                endpoint = '/api/generate/key-and-cert';
                formData.append('key_type', document.getElementById('kc-key-type').value);
                formData.append('validity_days', document.getElementById('kc-validity').value);
                formData.append('cn', document.getElementById('kc-cn').value);
                formData.append('o', document.getElementById('kc-o').value);
                formData.append('ou', document.getElementById('kc-ou').value);
                formData.append('c', document.getElementById('kc-c').value);
                formData.append('st', document.getElementById('kc-st').value);
                formData.append('l', document.getElementById('kc-l').value);
                formData.append('san_dns', document.getElementById('kc-san-dns').value);
                formData.append('san_ip', document.getElementById('kc-san-ip').value);
                formData.append('key_password', document.getElementById('kc-password').value);
                break;

            case 'csr':
                endpoint = '/api/generate/csr';
                formData.append('key_file', document.getElementById('csr-key-file').files[0]);
                formData.append('key_password', document.getElementById('csr-key-password').value);
                formData.append('cn', document.getElementById('csr-cn').value);
                formData.append('o', document.getElementById('csr-o').value);
                formData.append('ou', document.getElementById('csr-ou').value);
                formData.append('c', document.getElementById('csr-c').value);
                formData.append('st', document.getElementById('csr-st').value);
                formData.append('l', document.getElementById('csr-l').value);
                formData.append('san_dns', document.getElementById('csr-san-dns').value);
                formData.append('san_ip', document.getElementById('csr-san-ip').value);
                break;

            case 'self_signed':
                endpoint = '/api/generate/self-signed';
                formData.append('key_file', document.getElementById('ss-key-file').files[0]);
                formData.append('key_password', document.getElementById('ss-key-password').value);
                formData.append('validity_days', document.getElementById('ss-validity').value);
                formData.append('cn', document.getElementById('ss-cn').value);
                formData.append('o', document.getElementById('ss-o').value);
                formData.append('ou', document.getElementById('ss-ou').value);
                formData.append('c', document.getElementById('ss-c').value);
                formData.append('st', document.getElementById('ss-st').value);
                formData.append('l', document.getElementById('ss-l').value);
                formData.append('san_dns', document.getElementById('ss-san-dns').value);
                formData.append('san_ip', document.getElementById('ss-san-ip').value);
                break;

            case 'ca':
                endpoint = '/api/generate/ca';
                formData.append('key_file', document.getElementById('ca-key-file').files[0]);
                formData.append('key_password', document.getElementById('ca-key-password').value);
                formData.append('validity_days', document.getElementById('ca-validity').value);
                formData.append('cn', document.getElementById('ca-cn').value);
                formData.append('o', document.getElementById('ca-o').value);
                formData.append('ou', document.getElementById('ca-ou').value);
                formData.append('c', document.getElementById('ca-c').value);
                formData.append('st', document.getElementById('ca-st').value);
                formData.append('l', document.getElementById('ca-l').value);
                break;
        }

        try {
            const response = await fetch(endpoint, {
                method: 'POST',
                body: formData
            });

            const data = await response.json();

            if (response.ok) {
                displayGenerateResult(currentType, data);
                showToast(window.T.common.success);
            } else {
                showToast(data.detail, 'error');
            }
        } catch (err) {
            showToast(err.message, 'error');
        }
    });
}

function displayGenerateResult(type, data) {
    const resultDiv = document.getElementById('generate-result');
    const contentDiv = document.getElementById('result-content');
    resultDiv.classList.remove('d-none');

    const t = window.T.generate;
    let html = '';

    if (data.private_key) {
        html += `
            <div class="result-item">
                <div class="result-label">${window.T.convert.private_key}</div>
                <pre class="pem-output">${escapeHtml(data.private_key)}</pre>
                <div class="action-buttons">
                    <button class="btn btn-outline-primary btn-sm" onclick="copyToClipboard(\`${escapeJs(data.private_key)}\`)">
                        <i class="bi bi-clipboard"></i> ${window.T.convert.copy}
                    </button>
                    <button class="btn btn-primary btn-sm" onclick="downloadFile(\`${escapeJs(data.private_key)}\`, 'private_key.pem')">
                        <i class="bi bi-download"></i> ${t.download_key}
                    </button>
                </div>
            </div>
        `;
    }

    if (data.certificate) {
        html += `
            <div class="result-item">
                <div class="result-label">${window.T.convert.certificate}</div>
                <pre class="pem-output">${escapeHtml(data.certificate)}</pre>
                <div class="action-buttons">
                    <button class="btn btn-outline-primary btn-sm" onclick="copyToClipboard(\`${escapeJs(data.certificate)}\`)">
                        <i class="bi bi-clipboard"></i> ${window.T.convert.copy}
                    </button>
                    <button class="btn btn-primary btn-sm" onclick="downloadFile(\`${escapeJs(data.certificate)}\`, 'certificate.pem')">
                        <i class="bi bi-download"></i> ${t.download_cert}
                    </button>
                </div>
            </div>
        `;
    }

    if (data.csr) {
        html += `
            <div class="result-item">
                <div class="result-label">CSR</div>
                <pre class="pem-output">${escapeHtml(data.csr)}</pre>
                <div class="action-buttons">
                    <button class="btn btn-outline-primary btn-sm" onclick="copyToClipboard(\`${escapeJs(data.csr)}\`)">
                        <i class="bi bi-clipboard"></i> ${window.T.convert.copy}
                    </button>
                    <button class="btn btn-primary btn-sm" onclick="downloadFile(\`${escapeJs(data.csr)}\`, 'certificate.csr')">
                        <i class="bi bi-download"></i> ${t.download_csr}
                    </button>
                </div>
            </div>
        `;
    }

    contentDiv.innerHTML = html;
}

// ==================== SMART CONVERT PAGE ====================

// Conversion matrix: source format -> available target formats
const CONVERSION_MATRIX = {
    'pfx': { formats: ['pem', 'jks'], actions: ['extract_key', 'extract_cert'] },
    'p12': { formats: ['pem', 'jks'], actions: ['extract_key', 'extract_cert'] },
    'pem': { formats: ['pfx', 'der', 'p7b', 'jks'], actions: [] },
    'crt': { formats: ['pfx', 'der', 'p7b', 'jks'], actions: [] },
    'cer': { formats: ['pfx', 'der', 'p7b', 'jks'], actions: [] },
    'key': { formats: [], actions: [] },
    'der': { formats: ['pem'], actions: [] },
    'p7b': { formats: ['pem'], actions: [] },
    'p7c': { formats: ['pem'], actions: [] },
    'jks': { formats: ['pfx'], actions: [] },
    'keystore': { formats: ['pfx'], actions: [] }
};

let smartConvertState = {
    sourceFile: null,
    sourceFormat: null,
    targetFormat: null,
    targetAction: null
};

function initSmartConvertPage() {
    initDropZones();
    setupSmartFileUpload();
    setupFormatNodes();
    setupActionNodes();
    setupSmartConvertForm();
}

function setupSmartFileUpload() {
    const fileInput = document.getElementById('smart-file');
    const dropZone = document.querySelector('.drop-zone-large');

    if (!fileInput || !dropZone) return;

    fileInput.addEventListener('change', () => {
        if (fileInput.files.length) {
            handleSmartFileUpload(fileInput.files[0]);
        }
    });

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        if (e.dataTransfer.files.length) {
            fileInput.files = e.dataTransfer.files;
            handleSmartFileUpload(e.dataTransfer.files[0]);
        }
    });
}

function handleSmartFileUpload(file) {
    const extension = file.name.split('.').pop().toLowerCase();

    smartConvertState.sourceFile = file;
    smartConvertState.sourceFormat = extension;
    smartConvertState.targetFormat = null;
    smartConvertState.targetAction = null;

    // Update UI
    document.getElementById('uploaded-file-info').classList.remove('d-none');
    document.getElementById('uploaded-file-name').textContent = file.name;
    document.getElementById('uploaded-file-format').textContent = extension.toUpperCase();
    document.getElementById('no-file-hint').classList.add('d-none');

    // Update drop zone
    document.querySelector('.drop-zone-large').classList.add('has-file');

    // Update available conversions
    updateAvailableConversions(extension);

    // Hide conversion panel if open
    hideConversionPanel();
}

function updateAvailableConversions(sourceFormat) {
    const matrix = CONVERSION_MATRIX[sourceFormat] || { formats: [], actions: [] };

    // Reset all nodes
    document.querySelectorAll('.format-node').forEach(node => {
        node.classList.remove('active', 'source', 'selected');
    });
    document.querySelectorAll('.action-node').forEach(node => {
        node.classList.remove('active', 'selected');
    });

    // Mark source format
    const sourceNode = document.querySelector(`.format-node[data-format="${normalizeFormat(sourceFormat)}"]`);
    if (sourceNode) {
        sourceNode.classList.add('source');
    }

    // Enable target formats
    matrix.formats.forEach(format => {
        const node = document.querySelector(`.format-node[data-format="${format}"]`);
        if (node) {
            node.classList.add('active');
        }
    });

    // Enable actions
    matrix.actions.forEach(action => {
        const node = document.querySelector(`.action-node[data-action="${action}"]`);
        if (node) {
            node.classList.add('active');
        }
    });
}

function normalizeFormat(ext) {
    const map = {
        'pfx': 'pfx', 'p12': 'pfx',
        'pem': 'pem', 'crt': 'pem', 'cer': 'pem', 'key': 'pem',
        'der': 'der',
        'p7b': 'p7b', 'p7c': 'p7b',
        'jks': 'jks', 'keystore': 'jks'
    };
    return map[ext] || ext;
}

function setupFormatNodes() {
    document.querySelectorAll('.format-node').forEach(node => {
        node.addEventListener('click', () => {
            if (!node.classList.contains('active')) return;

            // Deselect other nodes
            document.querySelectorAll('.format-node').forEach(n => n.classList.remove('selected'));
            document.querySelectorAll('.action-node').forEach(n => n.classList.remove('selected'));

            node.classList.add('selected');
            smartConvertState.targetFormat = node.dataset.format;
            smartConvertState.targetAction = null;

            showConversionPanel();
        });
    });
}

function setupActionNodes() {
    document.querySelectorAll('.action-node').forEach(node => {
        node.addEventListener('click', () => {
            if (!node.classList.contains('active')) return;

            // Deselect other nodes
            document.querySelectorAll('.format-node').forEach(n => n.classList.remove('selected'));
            document.querySelectorAll('.action-node').forEach(n => n.classList.remove('selected'));

            node.classList.add('selected');
            smartConvertState.targetAction = node.dataset.action;
            smartConvertState.targetFormat = null;

            showConversionPanel();
        });
    });
}

function showConversionPanel() {
    const panel = document.getElementById('conversion-panel');
    const fromEl = document.getElementById('conversion-from');
    const toEl = document.getElementById('conversion-to');

    const sourceFormat = smartConvertState.sourceFormat.toUpperCase();
    let targetLabel = '';

    if (smartConvertState.targetFormat) {
        targetLabel = smartConvertState.targetFormat.toUpperCase();
    } else if (smartConvertState.targetAction) {
        targetLabel = smartConvertState.targetAction === 'extract_key' ?
            window.T.convert.types.extract_key :
            window.T.convert.types.extract_cert;
    }

    fromEl.textContent = sourceFormat;
    toEl.textContent = targetLabel;

    // Configure form fields based on conversion type
    configureConversionForm();

    panel.classList.remove('d-none');

    // Scroll to panel
    panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function hideConversionPanel() {
    document.getElementById('conversion-panel').classList.add('d-none');
    document.getElementById('convert-result').classList.add('d-none');

    // Clear selections
    document.querySelectorAll('.format-node').forEach(n => n.classList.remove('selected'));
    document.querySelectorAll('.action-node').forEach(n => n.classList.remove('selected'));

    smartConvertState.targetFormat = null;
    smartConvertState.targetAction = null;
}

function clearUploadedFile() {
    smartConvertState = {
        sourceFile: null,
        sourceFormat: null,
        targetFormat: null,
        targetAction: null
    };

    document.getElementById('smart-file').value = '';
    document.getElementById('uploaded-file-info').classList.add('d-none');
    document.getElementById('no-file-hint').classList.remove('d-none');
    document.querySelector('.drop-zone-large').classList.remove('has-file');

    // Reset all nodes
    document.querySelectorAll('.format-node').forEach(node => {
        node.classList.remove('active', 'source', 'selected');
    });
    document.querySelectorAll('.action-node').forEach(node => {
        node.classList.remove('active', 'selected');
    });

    hideConversionPanel();
}

function configureConversionForm() {
    // Hide all optional groups first
    ['source-password-group', 'target-password-group', 'alias-group',
     'friendly-name-group', 'key-format-group', 'split-export-group',
     'key-file-group', 'chain-file-group'].forEach(id => {
        document.getElementById(id).classList.add('d-none');
    });

    const sourceFormat = normalizeFormat(smartConvertState.sourceFormat);
    const targetFormat = smartConvertState.targetFormat;
    const targetAction = smartConvertState.targetAction;

    // Source password for PFX/JKS
    if (['pfx', 'p12', 'jks', 'keystore'].includes(smartConvertState.sourceFormat)) {
        document.getElementById('source-password-group').classList.remove('d-none');
        document.getElementById('source-password-label').textContent =
            sourceFormat === 'jks' ? window.T.convert.jks_password : window.T.convert.pfx_password;
    }

    // Target-specific fields
    if (targetFormat === 'pfx') {
        document.getElementById('target-password-group').classList.remove('d-none');
        document.getElementById('target-password-label').textContent = window.T.convert.pfx_password;
        document.getElementById('friendly-name-group').classList.remove('d-none');

        // If source is PEM, need key file
        if (sourceFormat === 'pem') {
            document.getElementById('key-file-group').classList.remove('d-none');
            document.getElementById('chain-file-group').classList.remove('d-none');
        }
    } else if (targetFormat === 'jks') {
        document.getElementById('target-password-group').classList.remove('d-none');
        document.getElementById('target-password-label').textContent = window.T.convert.jks_password;
        document.getElementById('alias-group').classList.remove('d-none');

        // If source is PEM, need key file
        if (sourceFormat === 'pem') {
            document.getElementById('key-file-group').classList.remove('d-none');
            document.getElementById('chain-file-group').classList.remove('d-none');
        }
    } else if (targetFormat === 'pem' && sourceFormat === 'pfx') {
        document.getElementById('key-format-group').classList.remove('d-none');
        document.getElementById('split-export-group').classList.remove('d-none');
    } else if (targetFormat === 'p7b' && sourceFormat === 'pem') {
        document.getElementById('chain-file-group').classList.remove('d-none');
    }

    // Action-specific fields
    if (targetAction === 'extract_key') {
        document.getElementById('key-format-group').classList.remove('d-none');
        document.getElementById('target-password-group').classList.remove('d-none');
        document.getElementById('target-password-label').textContent = window.T.convert.new_password;
    }
}

function setupSmartConvertForm() {
    const form = document.getElementById('smart-convert-form');
    if (!form) return;

    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const formData = new FormData();
        formData.append('file', smartConvertState.sourceFile);

        let endpoint = '';
        const sourceFormat = normalizeFormat(smartConvertState.sourceFormat);
        const targetFormat = smartConvertState.targetFormat;
        const targetAction = smartConvertState.targetAction;

        // Source password
        const sourcePassword = document.getElementById('source-password').value;
        const targetPassword = document.getElementById('target-password').value;

        if (targetAction === 'extract_key') {
            endpoint = '/api/convert/extract-key';
            formData.append('password', sourcePassword);
            formData.append('new_password', targetPassword);
            formData.append('key_format', document.querySelector('input[name="key-format"]:checked')?.value || 'pkcs8');
        } else if (targetAction === 'extract_cert') {
            endpoint = '/api/convert/extract-cert';
            formData.append('password', sourcePassword);
        } else if (sourceFormat === 'pfx' && targetFormat === 'pem') {
            endpoint = '/api/convert/pfx-to-pem';
            formData.append('password', sourcePassword);
            formData.append('key_format', document.querySelector('input[name="key-format"]:checked')?.value || 'pkcs8');
            if (document.getElementById('split-export').checked) {
                formData.append('export_mode', 'split');
            }
        } else if (sourceFormat === 'pfx' && targetFormat === 'jks') {
            endpoint = '/api/convert/pfx-to-jks';
            formData.append('pfx_password', sourcePassword);
            formData.append('jks_password', targetPassword);
            formData.append('alias', document.getElementById('conversion-alias').value || 'certificate');
        } else if (sourceFormat === 'jks' && targetFormat === 'pfx') {
            endpoint = '/api/convert/jks-to-pfx';
            formData.append('jks_password', sourcePassword);
            formData.append('pfx_password', targetPassword);
        } else if (sourceFormat === 'pem' && targetFormat === 'pfx') {
            endpoint = '/api/convert/pem-to-pfx';
            formData.append('cert_file', smartConvertState.sourceFile);
            formData.delete('file');
            const keyFile = document.getElementById('key-file').files[0];
            if (keyFile) formData.append('key_file', keyFile);
            const chainFile = document.getElementById('chain-file').files[0];
            if (chainFile) formData.append('chain_file', chainFile);
            formData.append('password', targetPassword);
            formData.append('friendly_name', document.getElementById('conversion-friendly-name').value || 'certificate');
        } else if (sourceFormat === 'pem' && targetFormat === 'der') {
            endpoint = '/api/convert/pem-to-der';
        } else if (sourceFormat === 'der' && targetFormat === 'pem') {
            endpoint = '/api/convert/der-to-pem';
        } else if (sourceFormat === 'pem' && targetFormat === 'p7b') {
            endpoint = '/api/convert/pem-to-p7b';
            formData.append('cert_file', smartConvertState.sourceFile);
            formData.delete('file');
            const chainFile = document.getElementById('chain-file').files[0];
            if (chainFile) formData.append('chain_file', chainFile);
        } else if (sourceFormat === 'p7b' && targetFormat === 'pem') {
            endpoint = '/api/convert/p7b-to-pem';
        } else if (sourceFormat === 'pem' && targetFormat === 'jks') {
            endpoint = '/api/convert/pem-to-jks';
            formData.append('cert_file', smartConvertState.sourceFile);
            formData.delete('file');
            const keyFile = document.getElementById('key-file').files[0];
            if (keyFile) formData.append('key_file', keyFile);
            const chainFile = document.getElementById('chain-file').files[0];
            if (chainFile) formData.append('chain_file', chainFile);
            formData.append('jks_password', targetPassword);
            formData.append('alias', document.getElementById('conversion-alias').value || 'certificate');
        }

        if (!endpoint) {
            showToast('Unsupported conversion', 'error');
            return;
        }

        try {
            const response = await fetch(endpoint, {
                method: 'POST',
                body: formData
            });

            // Check for binary response
            const isBinaryOutput = ['pem_to_pfx', 'pem_to_der', 'pem_to_p7b', 'pfx_to_jks', 'jks_to_pfx', 'pem_to_jks'].includes(
                `${sourceFormat}_to_${targetFormat}`
            ) || document.getElementById('split-export')?.checked;

            if (isBinaryOutput || response.headers.get('content-type')?.includes('octet-stream') ||
                response.headers.get('content-type')?.includes('zip')) {
                if (response.ok) {
                    const filename = response.headers.get('content-disposition')?.match(/filename="(.+)"/)?.[1] || 'output';
                    downloadBinaryResponse(response, filename);
                    showToast(window.T.common.success);
                } else {
                    const error = await response.json();
                    showToast(error.detail, 'error');
                }
                return;
            }

            const data = await response.json();

            if (response.ok) {
                displaySmartConvertResult(data);
                showToast(window.T.common.success);
            } else {
                showToast(data.detail, 'error');
            }
        } catch (err) {
            showToast(err.message, 'error');
        }
    });
}

function displaySmartConvertResult(data) {
    const resultDiv = document.getElementById('convert-result');
    const contentDiv = document.getElementById('result-content');
    resultDiv.classList.remove('d-none');

    let html = '';

    if (data.certificate) {
        html += `
            <div class="result-item">
                <div class="result-label">${window.T.convert.certificate}</div>
                <pre class="pem-output">${escapeHtml(data.certificate)}</pre>
                <div class="action-buttons">
                    <button class="btn btn-outline-primary btn-sm" onclick="copyToClipboard(\`${escapeJs(data.certificate)}\`)">
                        <i class="bi bi-clipboard"></i> ${window.T.convert.copy}
                    </button>
                    <button class="btn btn-primary btn-sm" onclick="downloadFile(\`${escapeJs(data.certificate)}\`, 'certificate.pem')">
                        <i class="bi bi-download"></i> ${window.T.convert.download}
                    </button>
                </div>
            </div>
        `;
    }

    if (data.private_key) {
        html += `
            <div class="result-item">
                <div class="result-label">${window.T.convert.private_key}</div>
                <pre class="pem-output">${escapeHtml(data.private_key)}</pre>
                <div class="action-buttons">
                    <button class="btn btn-outline-primary btn-sm" onclick="copyToClipboard(\`${escapeJs(data.private_key)}\`)">
                        <i class="bi bi-clipboard"></i> ${window.T.convert.copy}
                    </button>
                    <button class="btn btn-primary btn-sm" onclick="downloadFile(\`${escapeJs(data.private_key)}\`, 'private_key.key')">
                        <i class="bi bi-download"></i> ${window.T.convert.download}
                    </button>
                </div>
            </div>
        `;
    }

    if (data.chain) {
        html += `
            <div class="result-item">
                <div class="result-label">${window.T.convert.chain}</div>
                <pre class="pem-output">${escapeHtml(data.chain)}</pre>
                <div class="action-buttons">
                    <button class="btn btn-outline-primary btn-sm" onclick="copyToClipboard(\`${escapeJs(data.chain)}\`)">
                        <i class="bi bi-clipboard"></i> ${window.T.convert.copy}
                    </button>
                    <button class="btn btn-primary btn-sm" onclick="downloadFile(\`${escapeJs(data.chain)}\`, 'chain.pem')">
                        <i class="bi bi-download"></i> ${window.T.convert.download}
                    </button>
                </div>
            </div>
        `;
    }

    if (data.certificates) {
        html += `
            <div class="result-item">
                <div class="result-label">${window.T.convert.certificate}</div>
                <pre class="pem-output">${escapeHtml(data.certificates)}</pre>
                <div class="action-buttons">
                    <button class="btn btn-outline-primary btn-sm" onclick="copyToClipboard(\`${escapeJs(data.certificates)}\`)">
                        <i class="bi bi-clipboard"></i> ${window.T.convert.copy}
                    </button>
                    <button class="btn btn-primary btn-sm" onclick="downloadFile(\`${escapeJs(data.certificates)}\`, 'certificates.pem')">
                        <i class="bi bi-download"></i> ${window.T.convert.download}
                    </button>
                </div>
            </div>
        `;
    }

    contentDiv.innerHTML = html;

    // Scroll to result
    resultDiv.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// Utility functions
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function escapeJs(text) {
    return text.replace(/\\/g, '\\\\').replace(/`/g, '\\`').replace(/\$/g, '\\$');
}
