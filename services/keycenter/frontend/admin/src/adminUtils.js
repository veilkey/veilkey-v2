export function escapeHTML(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

export function formatJSON(value) {
    return JSON.stringify(value, null, 2);
}

export function isSelected(value, current) {
    return value === current ? ' is-selected' : '';
}

export function apiURL(path, query) {
    const url = new URL(path, window.location.origin);
    if (query) {
        Object.entries(query).forEach(([key, value]) => {
            if (value !== null && value !== undefined && value !== '') {
                url.searchParams.set(key, value);
            }
        });
    }
    return url.toString();
}

export function scopeClass(scope) {
    const normalized = String(scope || '').toLowerCase();
    if (normalized === 'external') return 'scope-external';
    if (normalized === 'temp') return 'scope-temp';
    return 'scope-local';
}

export function statusClass(status) {
    return String(status || 'ok').replace(/\s+/g, '_').toLowerCase();
}

export function renderStatusPill(label, className) {
    return '<span class="status-pill ' + escapeHTML(className) + '">' + escapeHTML(label) + '</span>';
}
