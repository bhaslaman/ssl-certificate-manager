/**
 * SSL Certificate Manager - Main JavaScript
 */

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
                break;
            case 'extract_cert':
                endpoint = '/api/convert/extract-cert';
                formData.append('file', document.getElementById('extract-cert-file').files[0]);
                formData.append('password', document.getElementById('extract-cert-password').value);
                break;
        }

        try {
            const response = await fetch(endpoint, {
                method: 'POST',
                body: formData
            });

            // Binary response (PFX, DER, P7B)
            if (['pem_to_pfx', 'pem_to_der', 'pem_to_p7b'].includes(currentType)) {
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

// Utility functions
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function escapeJs(text) {
    return text.replace(/\\/g, '\\\\').replace(/`/g, '\\`').replace(/\$/g, '\\$');
}
