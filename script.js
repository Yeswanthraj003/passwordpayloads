/**
 * Targeted Password Payload Generator — Frontend JavaScript
 * ==========================================================
 * Handles targeted profile payload generation, custom keyword fields,
 * real-time filtering, bulk copying, file export, and password analysis.
 */

let currentCandidates = [];
let filteredCandidates = [];

document.addEventListener('DOMContentLoaded', () => {
    initSidebar();
    initGenerator();
    initAnalyzer();
});

// Sidebar navigation toggle for mobile
function initSidebar() {
    const toggle = document.getElementById('menuToggle');
    const sidebar = document.getElementById('sidebar');
    const close = document.getElementById('sidebarClose');

    if (toggle) {
        toggle.addEventListener('click', () => sidebar.classList.toggle('open'));
    }
    if (close) {
        close.addEventListener('click', () => sidebar.classList.remove('open'));
    }

    // Global Sidebar Clear Database Button
    const sidebarClearDbBtn = document.getElementById('sidebarClearDbBtn');
    if (sidebarClearDbBtn) {
        sidebarClearDbBtn.addEventListener('click', () => {
            if (!confirm('Are you sure you want to clear all session activity, history, and generated data?')) {
                return;
            }

            fetch('/api/clear-activity', { method: 'POST' })
                .then(r => r.json())
                .then(data => {
                    if (data.success) {
                        showToast(data.message || 'Database and session history cleared!');
                        // If on dashboard, reload data
                        if (typeof loadDashboardData === 'function') {
                            loadDashboardData();
                        }
                    } else {
                        showToast('Failed to clear database.');
                    }
                })
                .catch(() => showToast('Error clearing database.'));
        });
    }

    document.addEventListener('click', (e) => {
        if (
            sidebar &&
            sidebar.classList.contains('open') &&
            !sidebar.contains(e.target) &&
            toggle &&
            !toggle.contains(e.target)
        ) {
            sidebar.classList.remove('open');
        }
    });
}

// Targeted Generator initialization
function initGenerator() {
    const generateBtn = document.getElementById('generateBtn');
    const clearBtn = document.getElementById('clearBtn');
    const searchInput = document.getElementById('searchFilter');
    const catFilter = document.getElementById('categoryFilter');
    const downloadBtn = document.getElementById('downloadBtn');
    const copyAllBtn = document.getElementById('copyAllBtn');
    const addKeywordBtn = document.getElementById('addKeywordBtn');

    if (!generateBtn) return; // Not on generator page

    // Dynamic Keyword Input Boxes
    if (addKeywordBtn) {
        addKeywordBtn.addEventListener('click', () => {
            const container = document.getElementById('keywordsContainer');
            const count = container.querySelectorAll('.keyword-item').length + 1;
            const div = document.createElement('div');
            div.className = 'keyword-item';
            div.innerHTML = `
                <input type="text" class="text-input keyword-field" placeholder="" maxlength="40">
                <button type="button" class="btn-remove-keyword" title="Remove" aria-label="Remove">&times;</button>
            `;
            div.querySelector('.btn-remove-keyword').addEventListener('click', () => div.remove());
            container.appendChild(div);
        });
    }

    // Trigger Generation
    generateBtn.addEventListener('click', handleGenerateProfile);

    // Allow Enter key inside inputs to trigger generation
    const form = document.getElementById('profileForm');
    if (form) {
        form.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && e.target.tagName !== 'TEXTAREA') {
                e.preventDefault();
                handleGenerateProfile();
            }
        });
    }

    // Clear form and results
    clearBtn.addEventListener('click', () => {
        if (form) form.reset();
        const container = document.getElementById('resultsContainer');
        if (container) container.style.display = 'none';
        currentCandidates = [];
        filteredCandidates = [];
        showToast('Form cleared.');
    });

    // Realtime search
    if (searchInput) {
        searchInput.addEventListener('input', applyFilters);
    }

    // Category filter
    if (catFilter) {
        catFilter.addEventListener('change', applyFilters);
    }

    // Download TXT
    if (downloadBtn) {
        downloadBtn.addEventListener('click', handleDownload);
    }

    // Copy All
    if (copyAllBtn) {
        copyAllBtn.addEventListener('click', handleCopyAll);
    }
}

// Generate targeted candidates from profile fields
async function handleGenerateProfile() {
    const firstName = (document.getElementById('firstName')?.value || '').trim();
    if (!firstName) {
        showToast('First Name is required!');
        document.getElementById('firstName')?.focus();
        return;
    }

    const lastName = (document.getElementById('lastName')?.value || '').trim();
    const nickname = (document.getElementById('nickname')?.value || '').trim();
    const dob = (document.getElementById('dob')?.value || '').trim();
    const birthYear = (document.getElementById('birthYear')?.value || '').trim();
    const favWord = (document.getElementById('favWord')?.value || '').trim();
    const favNumber = (document.getElementById('favNumber')?.value || '').trim();
    const otherInfo = (document.getElementById('otherInfo')?.value || '').trim();

    // Gather custom keywords from dynamic inputs + bulk textarea
    const keywordElements = document.querySelectorAll('.keyword-field');
    const customKeywords = [];
    keywordElements.forEach(el => {
        const val = el.value.trim();
        if (val) customKeywords.push(val);
    });

    const bulkKeywords = (document.getElementById('customKeywordsBulk')?.value || '').trim();
    if (bulkKeywords) {
        bulkKeywords.split('\n').forEach(k => {
            const clean = k.trim();
            if (clean && !customKeywords.includes(clean)) {
                customKeywords.push(clean);
            }
        });
    }

    const payload = {
        first_name: firstName,
        last_name: lastName,
        nickname: nickname,
        dob: dob,
        birth_year: birthYear,
        fav_word: favWord,
        fav_number: favNumber,
        other_info: otherInfo,
        custom_keywords: customKeywords,
    };

    const loading = document.getElementById('loadingOverlay');
    const container = document.getElementById('resultsContainer');

    if (loading) loading.style.display = 'flex';
    if (container) container.style.display = 'none';

    try {
        const res = await fetch('/api/generate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });

        const data = await res.json();

        if (!data.success) {
            showToast(data.message || 'Generation failed.');
            if (loading) loading.style.display = 'none';
            return;
        }

        currentCandidates = data.candidates || [];
        filteredCandidates = [...currentCandidates];

        // Update stats
        const totalCountEl = document.getElementById('totalCount');
        const catCountEl = document.getElementById('categoryCount');
        if (totalCountEl) totalCountEl.textContent = data.total;
        if (catCountEl) catCountEl.textContent = Object.keys(data.categories || {}).length;

        // Populate Category dropdown
        populateCategoryFilter(data.categories || {});

        // Reset search filter
        const searchInput = document.getElementById('searchFilter');
        if (searchInput) searchInput.value = '';

        // Render results
        renderResults(filteredCandidates);

        if (loading) loading.style.display = 'none';
        if (container) {
            container.style.display = 'block';
            container.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }

        showToast(`Generated ${data.total} targeted candidates!`);
    } catch (err) {
        if (loading) loading.style.display = 'none';
        showToast('Network error — please check backend server.');
        console.error(err);
    }
}

function populateCategoryFilter(categories) {
    const select = document.getElementById('categoryFilter');
    if (!select) return;

    select.innerHTML = '<option value="all">All Categories</option>';
    for (const [cat, count] of Object.entries(categories)) {
        const opt = document.createElement('option');
        opt.value = cat;
        opt.textContent = `${cat} (${count})`;
        select.appendChild(opt);
    }
}

function applyFilters() {
    const searchVal = (document.getElementById('searchFilter')?.value || '').toLowerCase();
    const catVal = document.getElementById('categoryFilter')?.value || 'all';

    filteredCandidates = currentCandidates.filter(c => {
        const matchSearch = !searchVal || c.text.toLowerCase().includes(searchVal);
        const matchCat = catVal === 'all' || c.category === catVal;
        return matchSearch && matchCat;
    });

    const totalCountEl = document.getElementById('totalCount');
    if (totalCountEl) totalCountEl.textContent = filteredCandidates.length;
    renderResults(filteredCandidates);
}

function renderResults(candidates) {
    const grid = document.getElementById('resultsGrid');
    if (!grid) return;

    if (candidates.length === 0) {
        grid.innerHTML = `
            <div style="text-align:center; padding:40px; color:var(--text-muted);">
                No matching password payloads found.
            </div>`;
        return;
    }

    const fragment = document.createDocumentFragment();

    candidates.forEach((c) => {
        const item = document.createElement('div');
        item.className = 'result-item';

        const text = document.createElement('span');
        text.className = 'result-text';
        text.textContent = c.text;

        const cat = document.createElement('span');
        cat.className = 'result-category';
        cat.textContent = c.category;

        const btn = document.createElement('button');
        btn.className = 'copy-btn';
        btn.textContent = 'Copy';
        btn.addEventListener('click', () => copyToClipboard(c.text, btn));

        item.appendChild(text);
        item.appendChild(cat);
        item.appendChild(btn);
        fragment.appendChild(item);
    });

    grid.innerHTML = '';
    grid.appendChild(fragment);
}

async function handleDownload() {
    if (filteredCandidates.length === 0) {
        showToast('No candidates to download.');
        return;
    }

    try {
        const res = await fetch('/api/download', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ candidates: filteredCandidates }),
        });

        if (!res.ok) {
            showToast('Download failed.');
            return;
        }

        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'targeted_passwords.txt';
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);

        showToast('Targeted wordlist downloaded!');
    } catch (err) {
        showToast('Download error.');
        console.error(err);
    }
}

function handleCopyAll() {
    if (filteredCandidates.length === 0) {
        showToast('No candidates to copy.');
        return;
    }

    const text = filteredCandidates.map(c => c.text).join('\n');
    navigator.clipboard.writeText(text).then(() => {
        showToast(`Copied ${filteredCandidates.length} payloads!`);
    }).catch(() => {
        showToast('Clipboard access denied.');
    });
}

// ──────────────────────────────────────────────────────────────
//  PASSWORD ANALYZER
// ──────────────────────────────────────────────────────────────
function initAnalyzer() {
    const input = document.getElementById('analyzerInput');
    const analyzeBtn = document.getElementById('analyzeBtn');
    const clearBtn = document.getElementById('clearAnalyzerBtn');
    const toggleBtn = document.getElementById('toggleVisibility');

    if (!input) return;

    analyzeBtn.addEventListener('click', handleAnalyze);

    input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            handleAnalyze();
        }
    });

    if (clearBtn) {
        clearBtn.addEventListener('click', () => {
            input.value = '';
            input.type = 'password';
            const res = document.getElementById('analysisResults');
            if (res) res.style.display = 'none';
        });
    }

    if (toggleBtn) {
        toggleBtn.addEventListener('click', () => {
            input.type = input.type === 'password' ? 'text' : 'password';
            toggleBtn.textContent = input.type === 'password' ? '👁' : '🙈';
        });
    }
}

async function handleAnalyze() {
    const input = document.getElementById('analyzerInput');
    const password = input.value;

    if (!password) {
        showToast('Please enter a password to analyse.');
        input.focus();
        return;
    }

    try {
        const res = await fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password }),
        });

        const data = await res.json();

        if (!data.success) {
            showToast(data.message || 'Analysis failed.');
            return;
        }

        renderAnalysis(data.analysis);
        const resEl = document.getElementById('analysisResults');
        if (resEl) {
            resEl.style.display = 'block';
            resEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    } catch (err) {
        showToast('Server error while evaluating password.');
        console.error(err);
    }
}

function renderAnalysis(analysis) {
    const strengthKey = analysis.strength.toLowerCase().replace(/\s+/g, '-');
    const fill = document.getElementById('strengthFill');
    const badge = document.getElementById('strengthBadge');
    const scoreEl = document.getElementById('strengthScore');

    const strengthCard = document.querySelector('.strength-card');
    if (strengthCard) {
        strengthCard.className = 'strength-card';
        strengthCard.classList.add(`strength-${strengthKey}`);
    }

    if (fill) {
        fill.style.width = analysis.score + '%';
        const colorMap = {
            'very-weak': '#ff4757',
            'weak': '#ff6b35',
            'medium': '#ffa502',
            'strong': '#7bed9f',
            'very-strong': '#00ff88',
        };
        fill.style.background = colorMap[strengthKey] || '#ffa502';
    }

    if (badge) {
        badge.textContent = analysis.strength;
        badge.className = 'strength-badge badge-' + strengthKey;
    }
    if (scoreEl) scoreEl.textContent = analysis.score;

    document.getElementById('bLength').textContent = analysis.length;
    document.getElementById('bUppercase').textContent = analysis.uppercase;
    document.getElementById('bLowercase').textContent = analysis.lowercase;
    document.getElementById('bDigits').textContent = analysis.digits;
    document.getElementById('bSpecial').textContent = analysis.special_characters;
    document.getElementById('bTypes').textContent = analysis.character_types_used;

    const weakCard = document.getElementById('weaknessesCard');
    const weakList = document.getElementById('weaknessList');

    if (analysis.weaknesses && analysis.weaknesses.length > 0) {
        weakCard.style.display = 'block';
        weakList.innerHTML = analysis.weaknesses
            .map(w => `<li>${escapeHtml(w)}</li>`)
            .join('');
    } else {
        weakCard.style.display = 'none';
    }

    const sugList = document.getElementById('suggestionList');
    if (sugList) {
        sugList.innerHTML = analysis.suggestions
            .map(s => `<li>${escapeHtml(s)}</li>`)
            .join('');
    }
}

function copyToClipboard(text, btn) {
    navigator.clipboard.writeText(text).then(() => {
        btn.textContent = 'Copied!';
        btn.classList.add('copied');
        setTimeout(() => {
            btn.textContent = 'Copy';
            btn.classList.remove('copied');
        }, 1500);
    }).catch(() => {
        showToast('Copy failed.');
    });
}

function showToast(message) {
    document.querySelectorAll('.toast').forEach(t => t.remove());

    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.textContent = message;
    document.body.appendChild(toast);

    setTimeout(() => toast.remove(), 2600);
}

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}
