export const pageConfig = {
    vaults: { label: '볼트', tabs: ['전체 볼트', 'Host Vault', '키 / 환경값'] },
    functions: { label: '함수', tabs: ['함수 목록', '연결 관리', '영향도', '실행'] },
    audit: { label: '감사', tabs: ['감사 로그'] },
    settings: { label: '설정', tabs: ['UI', '관리자'] }
};

export const routeEntries = [
    { page: 'vaults', tab: '전체 볼트', path: '/vaults/all' },
    { page: 'vaults', tab: 'Host Vault', path: '/vaults/host' },
    { page: 'functions', tab: '함수 목록', path: '/functions/list' },
    { page: 'functions', tab: '연결 관리', path: '/functions/bindings' },
    { page: 'functions', tab: '영향도', path: '/functions/impact' },
    { page: 'functions', tab: '실행', path: '/functions/run' },
    { page: 'audit', tab: '감사 로그', path: '/audit' },
    { page: 'settings', tab: 'UI', path: '/settings/ui' },
    { page: 'settings', tab: '관리자', path: '/settings/admin' }
];

export const routeByPath = Object.fromEntries(routeEntries.map((entry) => [entry.path, entry]));
