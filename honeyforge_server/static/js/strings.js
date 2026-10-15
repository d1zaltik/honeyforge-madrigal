// HoneyForge Central Russian Localization & Strings Dictionary
// All user-facing strings are defined strictly in this module.

const STRINGS = {
    app: {
        title: "HoneyForge",
        subtitle: "Центр управления ловушками",
        channel_connected: "Канал событий: подключено",
        channel_reconnecting: "Канал событий: переподключение...",
        operator_label: "Оператор",
        role_admin: "Администратор",
        role_analyst: "Аналитик",
        btn_logout: "Выйти",
        btn_login: "Войти в систему"
    },
    tabs: {
        live: "Лента событий",
        traps: "Парк ловушек",
        profiles: "Профили",
        sessions: "Сессии",
        honeytokens: "Honeytokens",
        alerts_ioc: "Оповещения и IoC",
        audit: "Журнал аудита",
        users_keystore: "Пользователи и KeyStore"
    },
    roles: {
        admin: "Главный администратор (CISO)",
        soc_lead: "Руководитель смены SOC",
        analyst_l2: "Старший аналитик L2 (Threat Hunter)",
        analyst_l1: "Дежурный аналитик L1 (Triage)",
        auditor: "Аудитор ИБ (Комплаенс)",
        analyst: "Аналитик SOC"
    },
    stats: {
        traps_online: "Ловушки онлайн",
        events_24h: "События за 24 ч",
        critical_events: "Критические события",
        captured_credentials: "Перехваченные учётные данные",
        honeytokens_triggered: "Honeytokens сработало",
        traps_breakdown: (low, med) => `Low: ${low} · Medium: ${med}`
    },
    sim: {
        title: "Контрольная проверка обнаружения",
        subtitle: "Запускает реальную атаку на ловушку и показывает, как быстро событие доходит до центра",
        btn_port_scan: "1. Сканирование портов (Low)",
        btn_ssh_brute: "2. Подбор паролей SSH (Medium)",
        btn_interactive: "3. Интерактивная сессия и загрузка файла (Medium)",
        btn_honeytoken: "4. Срабатывание honeytoken (Medium)",
        btn_disconnect: "5. Потеря связи: проверка буфера (Store & Forward)",
        status_idle: "Готово к запуску проверки",
        status_running: "Выполняется сетевое воздействие на ловушку...",
        status_result: (sec) => `Событие получено центром за ${sec} с`
    },
    filters: {
        trap: "Ловушка",
        all_traps: "Все ловушки",
        event_type: "Тип события",
        all_types: "Все типы",
        severity: "Важность",
        all_severities: "Все уровни",
        source_ip: "Источник (IP)",
        period: "Период",
        p_15m: "15 мин",
        p_1h: "1 ч",
        p_24h: "24 ч",
        p_all: "Всё время",
        btn_reset: "Сбросить фильтры"
    },
    event_types: {
        port_scan: "Сканирование порта",
        banner_probe: "Запрос баннера",
        auth_attempt: "Попытка входа",
        shell_command: "Команда",
        web_request: "HTTP-запрос",
        file_download: "Загрузка файла",
        honeytoken_triggered: "Срабатывание honeytoken",
        sql_injection: "SQL-инъекция"
    },
    severities: {
        low: "НИЗКИЙ",
        medium: "СРЕДНИЙ",
        high: "ВЫСОКИЙ",
        critical: "КРИТИЧЕСКИЙ"
    },
    statuses: {
        online: "Онлайн",
        offline: "Офлайн",
        no_comm: "Нет связи",
        active: "Активен",
        triggered: "Сработал"
    },
    traps: {
        title: "Парк ловушек (DMZ)",
        col_id: "ID",
        col_name: "Название",
        col_level: "Уровень",
        col_profile: "Профиль",
        col_services: "Сервисы и порты",
        col_dmz_ip: "Адрес в DMZ",
        col_mgmt_ip: "Mgmt-адрес",
        col_status: "Статус",
        col_last_seen: "Последняя связь",
        col_events_24h: "События за 24 ч",
        col_actions: "Действия",
        btn_register: "Зарегистрировать ловушку",
        act_deploy: "Развернуть",
        act_stop: "Остановить",
        act_update_cfg: "Обновить конфигурацию",
        act_rotate_creds: "Ротировать креды",
        act_change_profile: "Сменить профиль"
    },
    profiles: {
        title: "Профили ловушек",
        col_name: "Название",
        col_level: "Уровень",
        col_services: "Сервисы",
        col_attached: "Привязано ловушек",
        col_updated: "Дата изменения",
        col_actions: "Действия",
        btn_create: "Создать профиль",
        act_edit: "Изменить",
        act_copy: "Копировать",
        act_delete: "Удалить"
    },
    sessions: {
        title: "Интерактивные сессии (Medium)",
        col_id: "ID сессии",
        col_trap: "Ловушка",
        col_source: "Источник",
        col_proto: "Протокол",
        col_start: "Начало",
        col_duration: "Длительность",
        col_commands: "Команд",
        col_files: "Файлов",
        col_status: "Статус",
        col_action: "Действие",
        btn_open: "Открыть"
    },
    honeytokens: {
        title: "Токены-приманки Honeytokens",
        col_id: "ID",
        col_type: "Тип",
        col_location: "Где размещён",
        col_value: "Значение",
        col_status: "Статус",
        col_triggered_at: "Время срабатывания",
        col_attacker_ip: "IP нарушителя",
        btn_create: "Разместить honeytoken"
    },
    alerts_ioc: {
        rules_title: "Правила оповещений",
        col_rule_name: "Условие",
        col_threshold: "Порог N",
        col_window: "Окно (с)",
        col_trap: "Ловушка",
        col_enabled: "Включено",
        btn_add_rule: "Добавить правило",
        ioc_title: "Индикаторы компрометации (IoC)",
        btn_download_stix: "Скачать STIX 2.1 (JSON)",
        btn_download_csv: "Скачать CSV",
        col_ioc_type: "Тип",
        col_ioc_val: "Значение",
        col_first_seen: "Первое появление",
        col_last_seen: "Последнее появление",
        col_count: "Число",
        col_ioc_trap: "Ловушка"
    },
    audit: {
        title: "Журнал аудита действий",
        col_time: "Время",
        col_operator: "Оператор",
        col_action: "Действие",
        col_target: "Объект",
        col_result: "Результат",
        col_ip: "IP-адрес"
    }
};

// Normalizes any datetime string from backend to a valid UTC Date object
function parseUTCDate(dateStr) {
    if (!dateStr) return null;
    if (dateStr instanceof Date) return dateStr;
    let s = String(dateStr).trim();
    if (!s) return null;
    if (s.includes(" ") && !s.includes("T")) {
        s = s.replace(" ", "T");
    }
    // If no timezone offset (Z or +/-HH:MM), treat as UTC
    if (!s.endsWith("Z") && !/[+-]\d{2}:?\d{2}$/.test(s)) {
        s = s + "Z";
    }
    const d = new Date(s);
    return isNaN(d.getTime()) ? new Date(dateStr) : d;
}

// Formats timestamp strictly in Moscow Time (MSK / Europe/Moscow)
const mskTimeFormatter = new Intl.DateTimeFormat("ru-RU", {
    timeZone: "Europe/Moscow",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false
});

const mskDateTimeFormatter = new Intl.DateTimeFormat("ru-RU", {
    timeZone: "Europe/Moscow",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false
});

function formatTimeMSK(dateStr) {
    const d = parseUTCDate(dateStr);
    if (!d || isNaN(d.getTime())) return dateStr || "—";
    return mskTimeFormatter.format(d);
}

function formatDateTimeMSK(dateStr) {
    const d = parseUTCDate(dateStr);
    if (!d || isNaN(d.getTime())) return dateStr || "—";
    const parts = mskDateTimeFormatter.formatToParts(d);
    const get = (type) => parts.find(p => p.type === type)?.value || "";
    return `${get("year")}-${get("month")}-${get("day")} ${get("hour")}:${get("minute")}:${get("second")} МСК`;
}

function formatDateTimeLocal(dateStr) {
    return formatDateTimeMSK(dateStr);
}

function formatDateTimeUTC(dateStr) {
    return formatDateTimeMSK(dateStr);
}

function formatRelativeTime(dateStr) {
    return ""; // Fully removed: user prefers clean timestamps without relative time labels
}

// Inline Linear SVG Icons (Lucide style, 16-18px, currentColor)
const ICONS = {
    live: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline></svg>`,
    traps: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect><rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect><line x1="6" y1="6" x2="6.01" y2="6"></line><line x1="6" y1="18" x2="6.01" y2="18"></line></svg>`,
    profiles: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>`,
    sessions: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"></polyline><line x1="12" y1="19" x2="20" y2="19"></line></svg>`,
    honeytokens: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"></path></svg>`,
    alerts_ioc: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>`,
    audit: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="12" y1="18" x2="12" y2="12"></line><line x1="9" y1="15" x2="15" y2="15"></line></svg>`,
    users: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"></path><circle cx="9" cy="7" r="4"></circle><path d="M22 21v-2a4 4 0 0 0-3-3.87"></path><path d="M16 3.13a4 4 0 0 1 0 7.75"></path></svg>`,
    key: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="7.5" cy="15.5" r="5.5"></circle><path d="m21 2-9.6 9.6"></path><path d="m15.5 7.5 3 3L22 7l-3-3"></path></svg>`,
    lock: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>`,
    check: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>`,
    close: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>`,
    download: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>`,
    play: `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>`
};
