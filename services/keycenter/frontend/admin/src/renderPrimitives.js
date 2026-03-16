import { escapeHTML } from './adminUtils';

export function renderTargetOptions(options, selected) {
    return options.map((option) => `<option value="${escapeHTML(option.value)}"${option.value === selected ? ' selected' : ''}>${escapeHTML(option.label)}</option>`).join('');
}

export function renderKVGrid(entries) {
    return `<div class="inline-grid">${entries.map(([label, value]) => `
        <div class="kv">
            <span class="label">${escapeHTML(label)}</span>
            <span class="value">${escapeHTML(value)}</span>
        </div>
    `).join('')}</div>`;
}

export function renderMiniList(items, selectedKey, action, labelBuilder, badgeBuilder) {
    if (!items || !items.length) return '<div class="empty">표시할 항목이 없습니다.</div>';
    return `<div class="mini-list">${items.map((item) => {
        const key = typeof selectedKey === 'function' ? selectedKey(item) : item[selectedKey];
        return `
            <button class="mini-item${action.selected(item) ? ' active' : ''}" data-action="${escapeHTML(action.name)}" data-key="${escapeHTML(key)}">
                <span class="mini-item-main">${labelBuilder(item)}</span>
                ${badgeBuilder ? badgeBuilder(item) : ''}
            </button>
        `;
    }).join('')}</div>`;
}

export function renderTable(columns, rows, rowClassFn, rowAttrsFn) {
    if (!rows.length) return '<div class="empty">표시할 행이 없습니다.</div>';
    return `
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>${columns.map((column) => `<th>${escapeHTML(column.label)}</th>`).join('')}</tr>
                </thead>
                <tbody>
                    ${rows.map((row) => `
                        <tr class="${escapeHTML(rowClassFn ? rowClassFn(row) : '')}" ${rowAttrsFn ? rowAttrsFn(row) : ''}>
                            ${columns.map((column) => `<td>${column.render(row)}</td>`).join('')}
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
}

export function renderOptions(options, selected) {
    return options.map((option) => `<option value="${escapeHTML(option)}"${option === selected ? ' selected' : ''}>${escapeHTML(option)}</option>`).join('');
}
