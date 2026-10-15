"""
HoneyForge Presentation Builder v3.0
Generates a world-class 10-slide PowerPoint presentation (HoneyForge_Defense_Presentation.pptx)
calibrated precisely for a 5-minute defense + 3-minute Q&A session at UmirHack 2026 (Case «Мадригал»).
Includes high-res UI screenshots, animated screencast GIF, interactive architecture diagram,
SOC cyber-palette styling, and exhaustive slide-by-slide speaker notes.
"""
import os
import sys

# Ensure site-packages are accessible
if r'C:\умир\venv\Lib\site-packages' not in sys.path:
    sys.path.insert(0, r'C:\умир\venv\Lib\site-packages')

from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.enum.shapes import MSO_SHAPE

# --- Color Palette (Cyber SOC Theme) ---
COLOR_BG = RGBColor(13, 14, 17)          # #0d0e11 - Dark background
COLOR_CARD = RGBColor(24, 27, 36)        # #181b24 - Card surface
COLOR_CARD_DARK = RGBColor(18, 20, 27)   # #12141b - Deeper card
COLOR_BORDER = RGBColor(46, 52, 70)      # #2e3446 - Border gray
COLOR_AMBER = RGBColor(229, 142, 60)     # #e58e3c - Primary HoneyForge Amber
COLOR_AMBER_BRIGHT = RGBColor(245, 158, 11) # #f59e0b
COLOR_CYAN = RGBColor(56, 189, 248)      # #38bdf8 - Accent Cyan Glow
COLOR_GREEN = RGBColor(16, 185, 129)     # #10b981 - Success / Online
COLOR_RED = RGBColor(239, 68, 68)        # #ef4444 - Critical / Alert
COLOR_WHITE = RGBColor(243, 244, 246)    # #f3f4f6 - Text High Contrast
COLOR_GRAY = RGBColor(156, 163, 175)     # #9ca3af - Text Secondary
COLOR_MUTED = RGBColor(107, 114, 128)    # #6b7280 - Muted

FONT_TITLE = 'Segoe UI'
FONT_BODY = 'Segoe UI'
FONT_CODE = 'Consolas'

ASSETS_DIR = r'c:\umirhack\presentation_assets'
OUTPUT_FILE = r'c:\umirhack\HoneyForge_Defense_Presentation.pptx'


def set_slide_background(slide):
    """Draws full slide dark background."""
    bg_shape = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, Inches(13.333), Inches(7.5))
    bg_shape.fill.solid()
    bg_shape.fill.fore_color.rgb = COLOR_BG
    bg_shape.line.fill.background()


def add_header(slide, category_text, title_text, subtitle_text, timing_text):
    """Adds uniform modern header to content slides."""
    # Category badge
    cat_shape = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(0.36), Inches(3.2), Inches(0.32))
    cat_shape.fill.solid()
    cat_shape.fill.fore_color.rgb = RGBColor(17, 35, 56)
    cat_shape.line.color.rgb = COLOR_CYAN
    cat_shape.line.width = Pt(1)
    tf_cat = cat_shape.text_frame
    tf_cat.word_wrap = False
    p_cat = tf_cat.paragraphs[0]
    p_cat.text = f"// {category_text.upper()}"
    p_cat.font.name = FONT_CODE
    p_cat.font.size = Pt(9)
    p_cat.font.bold = True
    p_cat.font.color.rgb = COLOR_CYAN
    p_cat.alignment = PP_ALIGN.CENTER

    # Timing badge (right side)
    time_shape = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(10.6), Inches(0.36), Inches(1.9), Inches(0.32))
    time_shape.fill.solid()
    time_shape.fill.fore_color.rgb = RGBColor(35, 25, 15)
    time_shape.line.color.rgb = COLOR_AMBER
    time_shape.line.width = Pt(1)
    tf_time = time_shape.text_frame
    p_time = tf_time.paragraphs[0]
    p_time.text = f"⏱ {timing_text}"
    p_time.font.name = FONT_CODE
    p_time.font.size = Pt(9)
    p_time.font.bold = True
    p_time.font.color.rgb = COLOR_AMBER
    p_time.alignment = PP_ALIGN.CENTER

    # Title text
    tx_title = slide.shapes.add_textbox(Inches(0.75), Inches(0.72), Inches(11.8), Inches(0.55))
    tf_t = tx_title.text_frame
    tf_t.word_wrap = True
    p_t = tf_t.paragraphs[0]
    p_t.text = title_text
    p_t.font.name = FONT_TITLE
    p_t.font.size = Pt(21)
    p_t.font.bold = True
    p_t.font.color.rgb = COLOR_WHITE

    # Subtitle text
    tx_sub = slide.shapes.add_textbox(Inches(0.75), Inches(1.26), Inches(11.8), Inches(0.35))
    tf_s = tx_sub.text_frame
    tf_s.word_wrap = True
    p_s = tf_s.paragraphs[0]
    p_s.text = subtitle_text
    p_s.font.name = FONT_BODY
    p_s.font.size = Pt(11)
    p_s.font.color.rgb = COLOR_GRAY


def add_card(slide, left, top, width, height, title, items, accent_color=COLOR_AMBER):
    """Adds a structured information card with safe internal padding via dedicated textbox."""
    card = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(left), Inches(top), Inches(width), Inches(height))
    card.fill.solid()
    card.fill.fore_color.rgb = COLOR_CARD
    card.line.color.rgb = COLOR_BORDER
    card.line.width = Pt(1)

    # Dedicated textbox inside card to avoid text-to-border clipping
    tx = slide.shapes.add_textbox(Inches(left + 0.22), Inches(top + 0.16), Inches(width - 0.44), Inches(height - 0.28))
    tf = tx.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0

    # Title
    p0 = tf.paragraphs[0]
    p0.text = title
    p0.font.name = FONT_TITLE
    p0.font.size = Pt(12)
    p0.font.bold = True
    p0.font.color.rgb = accent_color
    p0.space_after = Pt(6)

    # Bullet items
    for item in items:
        p = tf.add_paragraph()
        p.text = f"▸ {item}"
        p.font.name = FONT_BODY
        p.font.size = Pt(9.5)
        p.font.color.rgb = COLOR_WHITE
        p.space_after = Pt(4)


def add_image_panel(slide, left, top, width, height, image_filename, caption_text, glow_color=COLOR_BORDER):
    """Embeds an image inside a framed container with a bottom caption bar."""
    frame = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(left), Inches(top), Inches(width), Inches(height))
    frame.fill.solid()
    frame.fill.fore_color.rgb = COLOR_CARD_DARK
    frame.line.color.rgb = glow_color
    frame.line.width = Pt(1.5)

    img_path = os.path.join(ASSETS_DIR, image_filename)
    if os.path.exists(img_path):
        img_left = Inches(left + 0.08)
        img_top = Inches(top + 0.08)
        img_width = Inches(width - 0.16)
        img_height = Inches(height - 0.5)
        slide.shapes.add_picture(img_path, img_left, img_top, width=img_width, height=img_height)

    # Caption box at bottom
    caption_box = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(left + 0.08), Inches(top + height - 0.44), Inches(width - 0.16), Inches(0.36))
    caption_box.fill.solid()
    caption_box.fill.fore_color.rgb = RGBColor(18, 22, 32)
    caption_box.line.fill.background()
    tf_c = caption_box.text_frame
    p_c = tf_c.paragraphs[0]
    p_c.text = caption_text
    p_c.font.name = FONT_CODE
    p_c.font.size = Pt(8.5)
    p_c.font.color.rgb = COLOR_CYAN
    p_c.alignment = PP_ALIGN.CENTER


def build_deck():
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6]

    # ==========================================
    # SLIDE 1: TITLE SLIDE (0:00 - 0:25)
    # ==========================================
    s1 = prs.slides.add_slide(blank_layout)
    set_slide_background(s1)

    pill1 = s1.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(0.75), Inches(3.4), Inches(0.32))
    pill1.fill.solid()
    pill1.fill.fore_color.rgb = RGBColor(35, 25, 15)
    pill1.line.color.rgb = COLOR_AMBER
    pill1.line.width = Pt(1)
    tf_p1 = pill1.text_frame
    p_p1 = tf_p1.paragraphs[0]
    p_p1.text = "⚡ UMIRHACK 2026 // КЕЙС МАДРИГАЛ"
    p_p1.font.name = FONT_CODE
    p_p1.font.size = Pt(9)
    p_p1.font.bold = True
    p_p1.font.color.rgb = COLOR_AMBER
    p_p1.alignment = PP_ALIGN.CENTER

    tx_main = s1.shapes.add_textbox(Inches(0.75), Inches(1.2), Inches(5.5), Inches(1.8))
    tf_m = tx_main.text_frame
    tf_m.word_wrap = True
    p_m1 = tf_m.paragraphs[0]
    p_m1.text = "HoneyForge"
    p_m1.font.name = FONT_TITLE
    p_m1.font.size = Pt(46)
    p_m1.font.bold = True
    p_m1.font.color.rgb = COLOR_AMBER_BRIGHT

    p_m2 = tf_m.add_paragraph()
    p_m2.text = "Платформа активной кибердецепции и Threat Intelligence для корпоративного SOC"
    p_m2.font.name = FONT_TITLE
    p_m2.font.size = Pt(14)
    p_m2.font.color.rgb = COLOR_WHITE
    p_m2.space_before = Pt(6)

    # 4 Feature Badges in 2x2 grid
    badge_data = [
        ("✓ Zero False Positives", COLOR_GREEN, 0.8, 3.1),
        ("✓ Stealth DMZ Изоляция", COLOR_CYAN, 3.5, 3.1),
        ("✓ 1-Click Деплой Агентов", COLOR_AMBER, 0.8, 3.55),
        ("✓ STIX 2.1 SIEM Экспорт", COLOR_WHITE, 3.5, 3.55),
    ]
    for b_text, b_color, bx, by in badge_data:
        b_shp = s1.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(bx), Inches(by), Inches(2.6), Inches(0.36))
        b_shp.fill.solid()
        b_shp.fill.fore_color.rgb = COLOR_CARD
        b_shp.line.color.rgb = b_color
        b_shp.line.width = Pt(1)
        tf_b = b_shp.text_frame
        p_b = tf_b.paragraphs[0]
        p_b.text = b_text
        p_b.font.name = FONT_CODE
        p_b.font.size = Pt(9)
        p_b.font.color.rgb = b_color
        p_b.alignment = PP_ALIGN.CENTER

    # Team & Meta Card
    card_meta = s1.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(4.15), Inches(5.3), Inches(2.65))
    card_meta.fill.solid()
    card_meta.fill.fore_color.rgb = COLOR_CARD
    card_meta.line.color.rgb = COLOR_BORDER
    card_meta.line.width = Pt(1)

    tx_meta = s1.shapes.add_textbox(Inches(1.02), Inches(4.32), Inches(4.85), Inches(2.35))
    tf_meta = tx_meta.text_frame
    tf_meta.word_wrap = True
    tf_meta.margin_left = tf_meta.margin_right = tf_meta.margin_top = tf_meta.margin_bottom = 0
    
    p_meta0 = tf_meta.paragraphs[0]
    p_meta0.text = "Паспорт решения и защита"
    p_meta0.font.name = FONT_TITLE
    p_meta0.font.size = Pt(12)
    p_meta0.font.bold = True
    p_meta0.font.color.rgb = COLOR_CYAN
    p_meta0.space_after = Pt(7)

    meta_lines = [
        ("Команда:", "HoneyForge Team"),
        ("Кейс:", "«Мадригал» — Deception & Honeypot Management"),
        ("Регламент:", "5 минут доклад + 3 минуты сессия вопросов (Q&A)"),
        ("Стенд Live:", "https://uniprotkb-transportation-las-websites.trycloudflare.com"),
        ("Верификация:", "100% требований ТЗ • 15/15 Pytest • 11/11 Stealth"),
    ]
    for lbl, val in meta_lines:
        pm = tf_meta.add_paragraph()
        pm.text = f"{lbl} {val}"
        pm.font.name = FONT_BODY
        pm.font.size = Pt(9.5)
        pm.font.color.rgb = COLOR_WHITE
        pm.space_after = Pt(3)

    add_image_panel(s1, 6.4, 1.1, 6.1, 5.7, "01_dashboard.png", "HoneyForge CISO Console — Live SOC Monitoring Dashboard", COLOR_AMBER)

    s1.notes_slide.notes_text_frame.text = (
        "СЛАЙД 1 (0:00 - 0:25)\n"
        "РЕЧЬ ДОКЛАДЧИКА:\n"
        "«Добрый день, уважаемые члены жюри и эксперты! Мы представляем проект HoneyForge — "
        "корпоративную платформу активной кибердецепции и Threat Intelligence, созданную для кейса «Мадригал».\n"
        "Сегодня классический периметр защиты размыт, а обнаружение злоумышленников внутри корпоративной сети занимает недели и месяцы. "
        "HoneyForge меняет правила игры: мы превращаем инфраструктуру компании в минное поле для атакующего, где любой несанкционированный шаг "
        "приводит к мгновенному обнаружению с абсолютной точностью — 100% Zero False Positives.\n"
        "Платформа полностью развернута, протестирована и доступна вживую. Перейдем к концепции решения!»"
    )

    # ==========================================
    # SLIDE 2: ПРОБЛЕМА И КОНЦЕПЦИЯ (0:25 - 0:55)
    # ==========================================
    s2 = prs.slides.add_slide(blank_layout)
    set_slide_background(s2)
    add_header(s2, "Концепция и Ценность", "Проблема обнаружения и подход HoneyForge", 
               "Почему традиционные SIEM/EDR слепы к скрытным атакам и как Deception решает эту задачу", "0:25 - 0:55 (30с)")

    add_card(s2, 0.8, 1.75, 5.4, 2.55, "Боли корпоративной безопасности (SIEM/EDR)", [
        "Alert Fatigue: тысячи алертов в день, аналитики SOC тонут в рутине",
        "Dwell Time: хакер находится в сети в среднем 200+ дней до обнаружения",
        "Сложность детекта легитимных утилит (Living-off-the-Land, PowerShell, SSH)",
        "Традиционные honeypot легко деанонимизируются и изолированы от процессов SOC"
    ], COLOR_RED)

    add_card(s2, 0.8, 4.45, 5.4, 2.45, "Решение HoneyForge: Активная децепция", [
        "Zero False Positives: легитимным сотрудникам незачем обращаться к ловушкам",
        "Детект на ранней стадии: разведка, латеральное движение (Lateral Movement)",
        "Honeytokens (приманки в коде и БД): мгновенный триггер при краже секретов",
        "Автоматическое обогащение: IOC, TTY-сессии, вредоносные пейлоады в карантин"
    ], COLOR_GREEN)

    add_image_panel(s2, 6.5, 1.75, 6.0, 5.15, "02_traps_park.png", "Парк ловушек HoneyForge: реальные IP, порты, статусы и привязка сервисов", COLOR_AMBER)

    s2.notes_slide.notes_text_frame.text = (
        "СЛАЙД 2 (0:25 - 0:55)\n"
        "РЕЧЬ ДОКЛАДЧИКА:\n"
        "«В чем главная боль современного SOC? Команды реагирования перегружены тысячами событий из SIEM и EDR. "
        "Среди шума критические атаки теряются, а злоумышленники месяцами перемещаются по сети, используя легитимные учетки и инструменты администрирования.\n"
        "HoneyForge решает эту проблему в корне через принцип Zero False Positives. "
        "В нашей системе ловушки и цифровые приманки мимикрируют под реальные сервисы компании: SSH-серверы, базы данных, API и токены в репозиториях. "
        "Сотрудникам они не нужны, поэтому любое касание приманки — это гарантированный инцидент 100% достоверности. Аналитик SOC не тратит время на проверку ложных срабатываний, а сразу начинает расследование!»"
    )

    # ==========================================
    # SLIDE 3: АРХИТЕКТУРА И СТЕК (0:55 - 1:30)
    # ==========================================
    s3 = prs.slides.add_slide(blank_layout)
    set_slide_background(s3)
    add_header(s3, "Архитектура & Stealth", "Бескомпромиссная изоляция и Технологический стек",
               "Zero-Trust разделение контуров DMZ и Management, маскировка под RUM-телеметрию и системные демоны", "0:55 - 1:30 (35с)")

    add_card(s3, 0.8, 1.75, 5.3, 2.55, "Архитектурная безопасность (Stealth & Isolation)", [
        "Строгое разделение сетей: sysmon_internal_dmz (ловушки) vs sysmon_internal_mgmt (ядро)",
        "Нулевой доступ к БД из ловушек: атакованный агент физически изолирован от ядра",
        "Маскировка телеметрии: агент шлет события на Edge Nginx под видом /cdn-cgi/rum",
        "Мимикрия демонов: процессы работают под именами rsyslogd и systemd-resolved"
    ], COLOR_CYAN)

    add_card(s3, 0.8, 4.45, 5.3, 2.45, "Технологический стек платформы", [
        "Backend: Python 3.11, FastAPI (async), SQLAlchemy 2.0, Pydantic v2",
        "База данных & KeyStore: PostgreSQL 15, AES-256-GCM + PBKDF2 (100,000 итераций)",
        "Edge & Gateway: Nginx Reverse Proxy, Server-Sent Events (SSE) реального времени",
        "Тестирование: Pytest (15/15), Playwright E2E, 11/11 проверок скрытности (Stealth Check)"
    ], COLOR_AMBER)

    # Custom Visual Architecture Diagram on the right
    arch_card = s3.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.35), Inches(1.75), Inches(6.2), Inches(5.15))
    arch_card.fill.solid()
    arch_card.fill.fore_color.rgb = COLOR_CARD_DARK
    arch_card.line.color.rgb = COLOR_CYAN
    arch_card.line.width = Pt(1.5)

    tx_at = s3.shapes.add_textbox(Inches(6.45), Inches(1.85), Inches(6.0), Inches(0.35))
    tf_at = tx_at.text_frame
    p_at = tf_at.paragraphs[0]
    p_at.text = "Схема сетевой изоляции и маскировки HoneyForge"
    p_at.font.name = FONT_TITLE
    p_at.font.size = Pt(11.5)
    p_at.font.bold = True
    p_at.font.color.rgb = COLOR_CYAN
    p_at.alignment = PP_ALIGN.CENTER

    # Diagram Block 1: DMZ Subnet
    b_dmz = s3.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.55), Inches(2.25), Inches(5.8), Inches(1.05))
    b_dmz.fill.solid()
    b_dmz.fill.fore_color.rgb = RGBColor(30, 22, 22)
    b_dmz.line.color.rgb = COLOR_RED
    b_dmz.line.width = Pt(1)
    tx_dmz = s3.shapes.add_textbox(Inches(6.65), Inches(2.32), Inches(5.6), Inches(0.9))
    tf_dmz = tx_dmz.text_frame
    tf_dmz.word_wrap = True
    tf_dmz.margin_left = tf_dmz.margin_right = tf_dmz.margin_top = tf_dmz.margin_bottom = 0
    p_dmz1 = tf_dmz.paragraphs[0]
    p_dmz1.text = "🔴 ИЗОЛИРОВАННЫЙ КОНТУР ЛОВУШЕК (DMZ: 172.28.0.0/24)"
    p_dmz1.font.name = FONT_CODE
    p_dmz1.font.size = Pt(9)
    p_dmz1.font.bold = True
    p_dmz1.font.color.rgb = COLOR_RED
    p_dmz2 = tf_dmz.add_paragraph()
    p_dmz2.text = "• Ловушка Low (systemd-resolved) | Ловушка Medium (rsyslogd) | Honeypots\n• Имитация Debian/Ubuntu, Tarpit-задержки | НЕТ доступа к Management сети"
    p_dmz2.font.name = FONT_BODY
    p_dmz2.font.size = Pt(8.5)
    p_dmz2.font.color.rgb = COLOR_WHITE

    # Arrow 1
    arr1 = s3.shapes.add_shape(MSO_SHAPE.DOWN_ARROW, Inches(9.25), Inches(3.38), Inches(0.4), Inches(0.24))
    arr1.fill.solid()
    arr1.fill.fore_color.rgb = COLOR_AMBER
    arr1.line.fill.background()

    # Masking Badge
    b_mask = s3.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.7), Inches(3.68), Inches(5.5), Inches(0.72))
    b_mask.fill.solid()
    b_mask.fill.fore_color.rgb = RGBColor(35, 25, 15)
    b_mask.line.color.rgb = COLOR_AMBER
    b_mask.line.width = Pt(1)
    tx_mask = s3.shapes.add_textbox(Inches(6.8), Inches(3.73), Inches(5.3), Inches(0.62))
    tf_mask = tx_mask.text_frame
    tf_mask.word_wrap = True
    tf_mask.margin_left = tf_mask.margin_right = tf_mask.margin_top = tf_mask.margin_bottom = 0
    p_m1 = tf_mask.paragraphs[0]
    p_m1.text = "🛡 Скрытная передача телеметрии: Edge Nginx Reverse Proxy"
    p_m1.font.name = FONT_CODE
    p_m1.font.size = Pt(9)
    p_m1.font.bold = True
    p_m1.font.color.rgb = COLOR_AMBER
    p_m2 = tf_mask.add_paragraph()
    p_m2.text = "POST /cdn-cgi/rum (Маскировка под Cloudflare RUM) + HMAC-SHA256 подпись"
    p_m2.font.name = FONT_BODY
    p_m2.font.size = Pt(8.5)
    p_m2.font.color.rgb = COLOR_WHITE

    # Arrow 2
    arr2 = s3.shapes.add_shape(MSO_SHAPE.DOWN_ARROW, Inches(9.25), Inches(4.46), Inches(0.4), Inches(0.24))
    arr2.fill.solid()
    arr2.fill.fore_color.rgb = COLOR_CYAN
    arr2.line.fill.background()

    # Diagram Block 2: MGMT Subnet
    b_mgmt = s3.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.55), Inches(4.76), Inches(5.8), Inches(1.95))
    b_mgmt.fill.solid()
    b_mgmt.fill.fore_color.rgb = RGBColor(16, 28, 42)
    b_mgmt.line.color.rgb = COLOR_CYAN
    b_mgmt.line.width = Pt(1)
    tx_mgmt = s3.shapes.add_textbox(Inches(6.65), Inches(4.84), Inches(5.6), Inches(1.8))
    tf_mgmt = tx_mgmt.text_frame
    tf_mgmt.word_wrap = True
    tf_mgmt.margin_left = tf_mgmt.margin_right = tf_mgmt.margin_top = tf_mgmt.margin_bottom = 0
    p_mg1 = tf_mgmt.paragraphs[0]
    p_mg1.text = "🔵 ЗАЩИЩЕННЫЙ КОНТУР УПРАВЛЕНИЯ (MGMT: 172.29.0.0/24)"
    p_mg1.font.name = FONT_CODE
    p_mg1.font.size = Pt(9)
    p_mg1.font.bold = True
    p_mg1.font.color.rgb = COLOR_CYAN
    p_mg2 = tf_mgmt.add_paragraph()
    p_mg2.text = "• HoneyForge Core C2 (FastAPI async + Event Bus + SSE Broadcast)\n• PostgreSQL 15: изоляция схем, аудит, IoC-хранилище\n• Cryptographic KeyStore: PBKDF2-HMAC-SHA256 + AES-256-GCM\n• Доступ операторов SOC: HTTPS / mTLS, 6 ролей (RBAC)"
    p_mg2.font.name = FONT_BODY
    p_mg2.font.size = Pt(8.5)
    p_mg2.font.color.rgb = COLOR_WHITE

    s3.notes_slide.notes_text_frame.text = (
        "СЛАЙД 3 (0:55 - 1:30)\n"
        "РЕЧЬ ДОКЛАДЧИКА:\n"
        "«Ключевой фактор успешной ловушки — чтобы атакующий ни на секунду не догадался, что он находится в песочнице.\n"
        "На диаграмме справа показана наша архитектура изоляции. Внутри контейнеров процессы имитируют стандартные системные демоны Linux — rsyslogd и systemd-resolved. "
        "Телеметрия с ловушки передается через Edge-прокси под видом обычного трафика мониторинга производительности Cloudflare RUM по пути /cdn-cgi/rum с HMAC-подписью.\n"
        "При этом соблюден строжайший принцип Zero-Trust: сеть ловушек DMZ полностью изолирована от управляющего ядра и базы данных. Даже если хакер получит root в ловушке, он физически не сможет обратиться к БД или ядру платформы.\n"
        "Backend платформы построен на асинхронном FastAPI и PostgreSQL с криптографическим KeyStore на базе AES-256-GCM!»"
    )

    # ==========================================
    # SLIDE 4: ПАРК ЛОВУШЕК И 1-CLICK ДЕПЛОЙ (1:30 - 2:05)
    # ==========================================
    s4 = prs.slides.add_slide(blank_layout)
    set_slide_background(s4)
    add_header(s4, "Парк Ловушек & Деплой", "Управление жизненным циклом и 1-Click Развертывание",
               "Автоматическая генерация манифестов Docker Compose, bash и PowerShell со встроенными крипто-ключами", "1:30 - 2:05 (35с)")

    add_card(s4, 0.8, 1.75, 5.4, 2.55, "Возможности управления ловушками", [
        "Гибкие профили интерактивности: Low-Interaction (SSH banner/tarpit) и Medium (Fake Shell)",
        "Параметры реализма: эмуляция Debian 12 / Ubuntu 22.04, правдоподобный uptime и хостнеймы",
        "Защита от сканеров: Tarpit-задержки ответов для противодействия автоматическому nmap",
        "Мониторинг доступности: Heartbeat-чеки со статусом Online/Offline в реальном времени"
    ], COLOR_AMBER)

    add_card(s4, 0.8, 4.45, 5.4, 2.45, "1-Click Автоматический Деплой", [
        "Генерация docker-compose.yml с готовой привязкой портов и маппингом сетей",
        "Генерация bash / curl однострочников для Linux серверов",
        "Генерация PowerShell скриптов для Windows инфраструктуры",
        "Автоматическая деривация уникального HMAC-токена агента (NODE_KEY) на лету"
    ], COLOR_CYAN)

    add_image_panel(s4, 6.5, 1.75, 6.0, 5.15, "03_trap_deploy_modal.png", "Модальное окно 1-Click деплоя: Docker Compose YAML, Bash и PowerShell", COLOR_AMBER)

    s4.notes_slide.notes_text_frame.text = (
        "СЛАЙД 4 (1:30 - 2:05)\n"
        "РЕЧЬ ДОКЛАДЧИКА:\n"
        "«На этом слайде вы видите, как оператор SOC развертывает новую ловушку буквально за 30 секунд.\n"
        "HoneyForge поддерживает профили различного уровня реализма: от Low-Interaction с эмуляцией баннеров и tarpit-задержками, истощающими сканеры злоумышленников, до Medium-Interaction с правдоподобной эмуляцией командной строки Linux.\n"
        "При нажатии кнопки 'Развернуть' платформа автоматически генерирует готовый Docker Compose файл, bash-скрипт или команду PowerShell. "
        "В каждый скрипт уже вшит уникальный криптографический HMAC-токен для защищенной авторизации агента на шлюзе телеметрии.\n"
        "Оператору достаточно скопировать команду и выполнить ее на любом хосте или сервере компании!»"
    )

    # ==========================================
    # SLIDE 5: СКРИНКАСТ / ДЕМО СОЗДАНИЯ (2:05 - 2:35)
    # ==========================================
    s5 = prs.slides.add_slide(blank_layout)
    set_slide_background(s5)
    add_header(s5, "Скринкаст & Демо", "Скринкаст: Процесс создания и активации ловушки",
               "Анимированная демонстрация полного цикла: от настройки профиля до регистрации в кластере", "2:05 - 2:35 (30с)")

    add_card(s5, 0.8, 1.75, 5.4, 1.6, "1. Настройка профиля реализма", [
        "Выбор уровня: Low (Port probe/Tarpit) или Medium (Shell emulator)",
        "Привязка сетевых сервисов: SSH (порт 2222), HTTP/API (порт 8080)",
        "Маскировка под системные демоны ОС: rsyslogd / systemd-resolved"
    ], COLOR_CYAN)

    add_card(s5, 0.8, 3.45, 5.4, 1.6, "2. Выпуск криптографических ключей", [
        "Мгновенная генерация уникального NODE_KEY и HMAC-секрета телеметрии",
        "Шифрование секрета в локальном KeyStore алгоритмом AES-256-GCM",
        "Безопасная доставка в деплой-команду без раскрытия паролей"
    ], COLOR_AMBER)

    add_card(s5, 0.8, 5.15, 5.4, 1.75, "3. Активация и мониторинг Live", [
        "Выполнение команды на целевом сервере в 1 клик",
        "Мгновенная регистрация на Edge-шлюзе телеметрии",
        "Переход в статус Online и появление в оперативной консоли SOC"
    ], COLOR_GREEN)

    # Animated screencast GIF
    add_image_panel(s5, 6.5, 1.75, 6.0, 5.15, "trap_workflow.gif", "Скринкаст создания и развертывания ловушки (Loop в полноэкранном режиме)", COLOR_GREEN)

    s5.notes_slide.notes_text_frame.text = (
        "СЛАЙД 5 (2:05 - 2:35)\n"
        "РЕЧЬ ДОКЛАДЧИКА:\n"
        "«Перед вами скринкаст, наглядно демонстрирующий полный цикл создания ловушки в живом интерфейсе HoneyForge.\n"
        "Смотрите: оператор выбирает профиль реализма, указывает имя сервиса и нажимает кнопку создания. "
        "В ту же секунду платформа генерирует уникальный криптографический ключ узла и предоставляет готовый деплой-манифест.\n"
        "После запуска контейнера ловушка мгновенно связывается с Edge-шлюзом телеметрии, подтверждает HMAC-подпись и загорается зеленым индикатором Online в консоли SOC. "
        "Весь процесс занимает менее минуты и не требует глубоких познаний в Linux-администрировании!»"
    )

    # ==========================================
    # SLIDE 6: ИНТЕРАКТИВНЫЕ СЕССИИ И ПЕРЕХВАТ MALWARE (2:35 - 3:15)
    # ==========================================
    s6 = prs.slides.add_slide(blank_layout)
    set_slide_background(s6)
    add_header(s6, "Анализ атак & Forensics", "Интерактивные сессии и Перехват вредоносного ПО",
               "Полнотекстовое TTY-логирование команд хакера, безопасный карантин артефактов и хеширование SHA-256", "2:35 - 3:15 (40с)")

    add_card(s6, 0.8, 1.75, 5.4, 2.55, "Мониторинг сессий в реальном времени", [
        "TTY-логирование: запись каждой набранной команды, аргументов и вывода терминала",
        "Индикаторы статуса: активные сессии с мигающим бейджем Live и таймингом",
        "Детект вредоносных действий: whoami, выгрузка скриптов через curl/wget, компиляция",
        "Полноценный аудит действий атакующего для формирования криминалистического отчета"
    ], COLOR_CYAN)

    add_card(s6, 0.8, 4.45, 5.4, 2.45, "Захват и Хеширование Malware (Forensics)", [
        "Автоматический перехват загружаемых пейлоадов в безопасный карантин платформы",
        "Мгновенный расчет криптографического хеша SHA-256 для проверки по Threat Intelligence",
        "Выявление попыток развертывания майнеров, веб-шеллов и бэкдоров",
        "Сохранение метаданных: IP атакующего, порт, целевой узел, точный timestamp"
    ], COLOR_RED)

    add_image_panel(s6, 6.5, 1.75, 6.0, 5.15, "07_session_modal.png", "Детальный просмотр сессии sess-8f12a9: TTY-лог и перехваченный пейлоад с SHA-256", COLOR_CYAN)

    s6.notes_slide.notes_text_frame.text = (
        "СЛАЙД 6 (2:35 - 3:15)\n"
        "РЕЧЬ ДОКЛАДЧИКА:\n"
        "«Что происходит, когда хакер подключается к нашей ловушке? Перед вами реальный пример перехвата сессии.\n"
        "HoneyForge в реальном времени ведет полнотекстовое TTY-логирование каждого действия злоумышленника: вы видите, как он выполняет команду whoami, затем скачивает вредоносный дроппер через curl, делает его исполняемым и пытается запустить.\n"
        "Система автоматически перехватывает этот бинарный файл, помещает его в защищенный карантин и прямо на лету рассчитывает криптографический хеш SHA-256. "
        "Аналитик SOC получает готовый артефакт для форензики, который можно мгновенно отправить в песочницу или сверить с базами Threat Intelligence. "
        "При этом злоумышленник уверен, что успешно взломал боевой сервер компании!»"
    )

    # ==========================================
    # SLIDE 7: HONEYTOKENS (3:15 - 3:50)
    # ==========================================
    s7 = prs.slides.add_slide(blank_layout)
    set_slide_background(s7)
    add_header(s7, "Honeytokens & Декорации", "Цифровые приманки и Корреляция скрытых угроз",
               "Размещение фиктивных секретов в коде, базах данных и на хостах для мгновенного обнаружения утечек", "3:15 - 3:50 (35с)")

    add_card(s7, 0.8, 1.75, 5.4, 2.55, "Типы цифровых приманок (Honeytokens)", [
        "Fake Cloud API Keys: поддельные AWS Access Key (AKIAIOSFODNN7EXAMPLE) в конфигах",
        "Fake Database Credentials: служебные учетки (prod_db_backup) в файлах приложений",
        "Fake SSH Deployment Keys: приватные ключи id_ed25519 на рабочих станциях и серверах",
        "Browser & Cookie Tokens: приманки в куках и локальном хранилище для перехвата инсайдеров"
    ], COLOR_AMBER)

    add_card(s7, 0.8, 4.45, 5.4, 2.45, "Мгновенная детекция и Корреляция", [
        "Любое обращение с фиктивным ключом = 100% доказательство компрометации",
        "Выявление латерального движения (Lateral Movement) до нанесения реального ущерба",
        "Эскалация в статус CRITICAL с мгновенным звуковым и визуальным оповещением SOC",
        "Полный трекинг: кто, откуда и с какого IP адреса попытался применить токен"
    ], COLOR_RED)

    add_image_panel(s7, 6.5, 1.75, 6.0, 5.15, "08_honeytokens.png", "Реестр активных Honeytokens: AWS API, DB Реплика, SSH Deploy Key", COLOR_AMBER)

    s7.notes_slide.notes_text_frame.text = (
        "СЛАЙД 7 (3:15 - 3:50)\n"
        "РЕЧЬ ДОКЛАДЧИКА:\n"
        "«Помимо сетевых ловушек, HoneyForge включает продвинутую подсистему Honeytokens — цифровых приманок.\n"
        "Мы генерируем реалистичные секреты и 'подбрасываем' их в корпоративные репозитории, конфигурационные файлы .env, резервные копии и историю терминалов. "
        "В системе представлены 3 ключевых типа приманок: поддельные ключи AWS IAM, учетные данные сервисных баз данных и приватные SSH-ключи для деплоя.\n"
        "Если внешний злоумышленник или недобросовестный инсайдер находит такой ключ и пробует использовать его для доступа к сервисам, HoneyForge мгновенно генерирует алерт наивысшего приоритета CRITICAL. "
        "Это позволяет остановить утечку на этапе разведки, пока хакер еще не добрался до реальных данных!»"
    )

    # ==========================================
    # SLIDE 8: THREAT INTELLIGENCE & SIEM ЭКСПОРТ (3:50 - 4:20)
    # ==========================================
    s8 = prs.slides.add_slide(blank_layout)
    set_slide_background(s8)
    add_header(s8, "Интеграция & Threat Intelligence", "Индикаторы компрометации (IoC) и Экспорт в SIEM",
               "Автоматическая выгрузка улик в стандарте STIX 2.1 JSON и CSV для мгновенной интеграции с MaxPatrol, KUMA и Splunk", "3:50 - 4:20 (30с)")

    add_card(s8, 0.8, 1.75, 5.4, 2.55, "Обогащение SOC данными Threat Intelligence", [
        "Сбор ключевых IOC: IP атакующего, User-Agent, порты, хеши файлов (SHA-256)",
        "Гранулярные уровни опасности: Critical, High, Medium, Low с детальным описанием вектора",
        "Очередь инцидентов с функцией 'Принять все' и подтверждением отработки аналитиком",
        "Server-Sent Events (SSE): доставка алертов в браузер дежурного оператора без перезагрузки"
    ], COLOR_CYAN)

    add_card(s8, 0.8, 4.45, 5.4, 2.45, "Экспорт по индустриальным стандартам", [
        "STIX 2.1 JSON: международный стандарт обмена киберразведкой (OASIS Standard)",
        "Прямой импорт в SIEM/SOAR: MaxPatrol SIEM, Kaspersky KUMA, Splunk, OpenCTI, MISP",
        "CSV Экспорт: табличная выгрузка для оперативных отчетов руководству и комплаенс",
        "Интеграция с NGFW / WAF: возможность автоматической блокировки IP злоумышленника"
    ], COLOR_GREEN)

    add_image_panel(s8, 6.5, 1.75, 6.0, 5.15, "09_alerts_and_ioc.png", "Таблица IoC и панель оповещений с 1-Click экспортом STIX 2.1 и CSV", COLOR_CYAN)

    s8.notes_slide.notes_text_frame.text = (
        "СЛАЙД 8 (3:50 - 4:20)\n"
        "РЕЧЬ ДОКЛАДЧИКА:\n"
        "«Любая система безопасности ценна тем, насколько бесшовно она встраивается в существующий процесс SOC.\n"
        "HoneyForge автоматически консолидирует все собранные улики в структурированную таблицу индикаторов компрометации (IoC): IP-адреса, User-Agent, атакованные учетные записи и хеши пейлоадов.\n"
        "Мы реализовали экспорт в стандарт STIX 2.1 JSON — это международный формат обмена киберразведкой, поддерживаемый ведущими российскими и зарубежными SIEM/SOAR системами, включая MaxPatrol SIEM, Kaspersky KUMA, OpenCTI и Splunk. "
        "Аналитик может в один клик выгрузить STIX 2.1 бандл или CSV-отчет, либо настроить автоматический пуш индикаторов в межсетевой экран для мгновенной блокировки атакующего периметром!»"
    )

    # ==========================================
    # SLIDE 9: БЕЗОПАСНОСТЬ: RBAC И CRYPTO KEYSTORE (4:20 - 4:45)
    # ==========================================
    s9 = prs.slides.add_slide(blank_layout)
    set_slide_background(s9)
    add_header(s9, "Безопасность Платформы", "Ролевая модель доступа (RBAC) и Crypto KeyStore",
               "6 ролей для команды SOC в соответствии со стандартами Enterprise и защита криптографических ключей узлов", "4:20 - 4:45 (25с)")

    add_card(s9, 0.8, 1.75, 5.4, 2.55, "Матрица ролей SOC (6 Enterprise Ролей)", [
        "CISO (Главный администратор): полный контроль политик, KeyStore и конфигурации",
        "SOC Lead (Руководитель смены): управление деплоем ловушек, Honeytokens и аналитика",
        "Senior Analyst L2: расследование инцидентов, анализ сессий и перехваченного malware",
        "Watcher L1: оперативный мониторинг живой ленты событий и подтверждение алертов",
        "Compliance Auditor: аудит действий операторов и комплаенс-отчетность (Read-Only)",
        "SOC Analyst: базовый профиль для работы с очередью инцидентов"
    ], COLOR_CYAN)

    add_card(s9, 0.8, 4.45, 5.4, 2.45, "Криптографический KeyStore", [
        "Безопасное хранение мастер-ключей (NODE_KEY), HMAC-секретов и токенов агентов",
        "Криптографическая защита: алгоритм шифрования AES-256-GCM",
        "Деривация мастер-ключа: PBKDF2-HMAC-SHA256 с 100 000 итераций",
        "Изоляция учетных данных операторов: безопасное хеширование паролей Argon2 / Bcrypt"
    ], COLOR_AMBER)

    add_image_panel(s9, 6.5, 1.75, 6.0, 5.15, "10_users_and_keystore.png", "Управление операторами SOC и защищенный криптографический KeyStore", COLOR_BORDER)

    s9.notes_slide.notes_text_frame.text = (
        "СЛАЙД 9 (4:20 - 4:45)\n"
        "РЕЧЬ ДОКЛАДЧИКА:\n"
        "«Платформа кибердецепции сама по себе является критическим элементом инфраструктуры, поэтому требования к ее внутренней безопасности максимальны.\n"
        "В HoneyForge реализована полноценная ролевая модель доступа из 6 гранулярных ролей: от CISO и руководителя смены SOC до аналитиков L2, дежурных L1 и внешних аудиторов ИБ. "
        "Каждое действие логируется, а права строго разграничены.\n"
        "Все секреты платформы — ключи регистрации ловушек NODE_KEY, HMAC-токены телеметрии и токены приманок — защищены встроенным криптографическим KeyStore. "
        "Ключи шифруются симметричным шифром AES-256-GCM с деривацией ключа через PBKDF2 со ста тысячами итераций!»"
    )

    # ==========================================
    # SLIDE 10: ИТОГИ, ПУБЛИЧНЫЙ СТЕНД И Q&A (4:45 - 5:00)
    # ==========================================
    s10 = prs.slides.add_slide(blank_layout)
    set_slide_background(s10)
    add_header(s10, "Результаты & Q&A", "Итоги реализации и готовность к внедрению",
               "Полное соответствие требованиям ТЗ, развернутый стенд и готовность к вопросам жюри", "4:45 - 5:00 (15с)")

    add_card(s10, 0.8, 1.75, 5.4, 2.55, "Ключевые достижения проекта", [
        "100% требований кейса «Мадригал» полностью реализовано и протестировано",
        "15/15 Pytest тестов пройдено (Auth, Coverage, Realism, Sessions, Keystore)",
        "11/11 проверок скрытности (Stealth Audit passed: DMZ, RUM, rsyslogd)",
        "Готовность к промышленной эксплуатации: 0 ложных срабатываний, STIX 2.1"
    ], COLOR_GREEN)

    # Live demo access card
    card_demo = s10.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(4.45), Inches(5.4), Inches(2.45))
    card_demo.fill.solid()
    card_demo.fill.fore_color.rgb = COLOR_CARD
    card_demo.line.color.rgb = COLOR_CYAN
    card_demo.line.width = Pt(1.5)

    tx_dm = s10.shapes.add_textbox(Inches(1.02), Inches(4.62), Inches(4.96), Inches(2.15))
    tf_dm = tx_dm.text_frame
    tf_dm.word_wrap = True
    tf_dm.margin_left = tf_dm.margin_right = tf_dm.margin_top = tf_dm.margin_bottom = 0
    
    p_dm0 = tf_dm.paragraphs[0]
    p_dm0.text = "🌐 Публичный стенд для тестирования жюри"
    p_dm0.font.name = FONT_TITLE
    p_dm0.font.size = Pt(12)
    p_dm0.font.bold = True
    p_dm0.font.color.rgb = COLOR_CYAN
    p_dm0.space_after = Pt(6)

    demo_lines = [
        "Ссылка: https://uniprotkb-transportation-las-websites.trycloudflare.com",
        "Логин: admin (CISO / Главный администратор)",
        "Учетные записи: CISO, SOC Lead, Analyst L2, L1, Auditor (в README.md)",
        "Быстрый запуск локально: docker compose up -d --build",
    ]
    for dline in demo_lines:
        pdl = tf_dm.add_paragraph()
        pdl.text = f"▸ {dline}"
        pdl.font.name = FONT_CODE
        pdl.font.size = Pt(9.5)
        pdl.font.color.rgb = COLOR_WHITE
        pdl.space_after = Pt(4)

    # Left bottom: Live demo access card
    card_demo = s10.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(4.45), Inches(5.4), Inches(2.45))
    card_demo.fill.solid()
    card_demo.fill.fore_color.rgb = COLOR_CARD
    card_demo.line.color.rgb = COLOR_CYAN
    card_demo.line.width = Pt(1.5)

    tx_dm = s10.shapes.add_textbox(Inches(1.02), Inches(4.60), Inches(4.96), Inches(2.15))
    tf_dm = tx_dm.text_frame
    tf_dm.word_wrap = True
    tf_dm.margin_left = tf_dm.margin_right = tf_dm.margin_top = tf_dm.margin_bottom = 0
    
    p_dm0 = tf_dm.paragraphs[0]
    p_dm0.text = "🌐 Доступ к стенду для экспертов жюри"
    p_dm0.font.name = FONT_TITLE
    p_dm0.font.size = Pt(12)
    p_dm0.font.bold = True
    p_dm0.font.color.rgb = COLOR_CYAN
    p_dm0.space_after = Pt(5)

    demo_lines = [
        "Для жюри: логин jury • пароль jury2026 (Режим просмотра)",
        "Кнопка на форме: «Быстрый вход для жюри» (в 1 клик)",
        "Для CISO: логин admin • пароль zd4maiMGqDrbARkXKbQDJQ",
        "Публичный URL: https://uniprotkb-transportation-las-websites.trycloudflare.com",
    ]
    for dline in demo_lines:
        pdl = tf_dm.add_paragraph()
        pdl.text = f"▸ {dline}"
        pdl.font.name = FONT_CODE
        pdl.font.size = Pt(9)
        pdl.font.color.rgb = COLOR_WHITE
        pdl.space_after = Pt(3.5)

    # Right top: Q&A Header Card
    qa_card = s10.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.5), Inches(1.75), Inches(6.0), Inches(1.5))
    qa_card.fill.solid()
    qa_card.fill.fore_color.rgb = COLOR_CARD_DARK
    qa_card.line.color.rgb = COLOR_AMBER
    qa_card.line.width = Pt(1.5)

    tx_qa = s10.shapes.add_textbox(Inches(6.7), Inches(1.88), Inches(5.6), Inches(1.2))
    tf_qa = tx_qa.text_frame
    tf_qa.word_wrap = True
    tf_qa.margin_left = tf_qa.margin_right = tf_qa.margin_top = tf_qa.margin_bottom = 0

    p_qa1 = tf_qa.paragraphs[0]
    p_qa1.text = "Спасибо за внимание!"
    p_qa1.font.name = FONT_TITLE
    p_qa1.font.size = Pt(23)
    p_qa1.font.bold = True
    p_qa1.font.color.rgb = COLOR_AMBER_BRIGHT
    p_qa1.alignment = PP_ALIGN.CENTER
    p_qa1.space_after = Pt(4)

    p_qa2 = tf_qa.add_paragraph()
    p_qa2.text = "Готовы ответить на вопросы экспертов"
    p_qa2.font.name = FONT_TITLE
    p_qa2.font.size = Pt(15)
    p_qa2.font.bold = True
    p_qa2.font.color.rgb = COLOR_CYAN
    p_qa2.alignment = PP_ALIGN.CENTER
    p_qa2.space_after = Pt(3)

    p_qa3 = tf_qa.add_paragraph()
    p_qa3.text = "⏱ Регламент ответов на вопросы: 3 минуты"
    p_qa3.font.name = FONT_CODE
    p_qa3.font.size = Pt(9.5)
    p_qa3.font.color.rgb = COLOR_GRAY
    p_qa3.alignment = PP_ALIGN.CENTER

    # Right bottom: Dedicated QR Code Card
    qr_card = s10.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.5), Inches(3.40), Inches(6.0), Inches(3.50))
    qr_card.fill.solid()
    qr_card.fill.fore_color.rgb = COLOR_CARD
    qr_card.line.color.rgb = COLOR_CYAN
    qr_card.line.width = Pt(1.5)

    # QR Code Image Frame
    qr_frame = s10.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.75), Inches(3.60), Inches(2.6), Inches(2.6))
    qr_frame.fill.solid()
    qr_frame.fill.fore_color.rgb = RGBColor(255, 255, 255)
    qr_frame.line.fill.background()

    qr_path = os.path.join(ASSETS_DIR, "jury_qr_code.png")
    if os.path.exists(qr_path):
        s10.shapes.add_picture(qr_path, Inches(6.80), Inches(3.65), width=Inches(2.5), height=Inches(2.5))

    # Caption under QR
    tx_qrcap = s10.shapes.add_textbox(Inches(6.6), Inches(6.25), Inches(2.9), Inches(0.5))
    tf_qrcap = tx_qrcap.text_frame
    p_qc = tf_qrcap.paragraphs[0]
    p_qc.text = "📱 QR-код для мгновенного входа"
    p_qc.font.name = FONT_CODE
    p_qc.font.size = Pt(8.5)
    p_qc.font.bold = True
    p_qc.font.color.rgb = COLOR_CYAN
    p_qc.alignment = PP_ALIGN.CENTER

    # Text instructions next to QR code
    tx_qrinfo = s10.shapes.add_textbox(Inches(9.55), Inches(3.60), Inches(2.75), Inches(3.0))
    tf_qrinfo = tx_qrinfo.text_frame
    tf_qrinfo.word_wrap = True
    tf_qrinfo.margin_left = tf_qrinfo.margin_right = tf_qrinfo.margin_top = tf_qrinfo.margin_bottom = 0

    p_qi1 = tf_qrinfo.paragraphs[0]
    p_qi1.text = "Вход без ввода пароля:"
    p_qi1.font.name = FONT_TITLE
    p_qi1.font.size = Pt(12)
    p_qi1.font.bold = True
    p_qi1.font.color.rgb = COLOR_AMBER
    p_qi1.space_after = Pt(6)

    p_qi2 = tf_qrinfo.add_paragraph()
    p_qi2.text = "Наведите камеру смартфона на QR-код для открытия веб-интерфейса HoneyForge.\nАвторизация происходит мгновенно в 1 клик!"
    p_qi2.font.name = FONT_BODY
    p_qi2.font.size = Pt(9.5)
    p_qi2.font.color.rgb = COLOR_WHITE
    p_qi2.space_after = Pt(8)

    p_qi3 = tf_qrinfo.add_paragraph()
    p_qi3.text = "✓ Роль: Эксперт жюри\n✓ Полный просмотр SOC\n✓ TTY-сессии и IoC STIX\n✓ Безопасный Read-Only"
    p_qi3.font.name = FONT_CODE
    p_qi3.font.size = Pt(8.5)
    p_qi3.font.color.rgb = COLOR_GREEN

    s10.notes_slide.notes_text_frame.text = (
        "СЛАЙД 10 (4:45 - 5:00)\n"
        "РЕЧЬ ДОКЛАДЧИКА:\n"
        "«Подводя итог: нами создано законченное, надежное и готовое к боевой эксплуатации решение. "
        "Все требования кейса «Мадригал» закрыты на 100%, что подтверждается 15 успешными unit-тестами и полным аудитом скрытности.\n"
        "Уважаемые эксперты! Прямо сейчас на слайде представлен QR-код: вы можете навести камеру своего телефона, "
        "и система мгновенно откроет интерфейс HoneyForge под ролью Эксперта Жюри — без необходимости вручную вводить пароль! "
        "Вам доступен полный просмотр ленты атак, парка ловушек, интерактивных сессий и IoC-базы.\n"
        "Спасибо за внимание! Наша команда готова ответить на ваши вопросы!»"
    )

    prs.save(OUTPUT_FILE)
    print(f"[SUCCESS] Presentation generated successfully: {OUTPUT_FILE}")


if __name__ == '__main__':
    build_deck()
