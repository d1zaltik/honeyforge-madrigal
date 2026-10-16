"""
HoneyForge Presentation Builder v4.0
Generates a polished 10-slide PowerPoint presentation (HoneyForge_Defense_Presentation.pptx)
for UmirHack 2026 (Case «Мадригал»).

Key updates in v4.0:
- Slide 1: Team «самсунг», 4 members with specific roles (Igor Firsov as Captain/Architect),
  prominent QR Code with white base and direct 1-Click zero-auth jury demo link.
- Completely removed all timing intervals (no ⏱ badges or time markers on slides).
- Embedded animated GIF (trap_workflow.gif) on Slide 5 showcasing trap creation workflow.
- Eliminated redundant text and visual clutter, ensuring high contrast cyber SOC theme.
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


def add_header(slide, category_text, title_text, subtitle_text):
    """Adds uniform modern header to content slides without any time markers."""
    # Category badge
    cat_shape = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(0.36), Inches(3.6), Inches(0.32))
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
    # SLIDE 1: ТИТУЛЬНЫЙ СЛАЙД (КОМАНДА «САМСУНГ» + QR ДЛЯ ЖЮРИ)
    # ==========================================
    s1 = prs.slides.add_slide(blank_layout)
    set_slide_background(s1)

    # Pill: UmirHack 2026 // Кейс Мадригал
    pill1 = s1.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(0.65), Inches(3.6), Inches(0.34))
    pill1.fill.solid()
    pill1.fill.fore_color.rgb = RGBColor(35, 25, 15)
    pill1.line.color.rgb = COLOR_AMBER
    pill1.line.width = Pt(1)
    tf_p1 = pill1.text_frame
    p_p1 = tf_p1.paragraphs[0]
    p_p1.text = "UMIRHACK 2026 // КЕЙС МАДРИГАЛ"
    p_p1.font.name = FONT_CODE
    p_p1.font.size = Pt(9.5)
    p_p1.font.bold = True
    p_p1.font.color.rgb = COLOR_AMBER
    p_p1.alignment = PP_ALIGN.CENTER

    # Main Brand & Subtitle
    tx_main = s1.shapes.add_textbox(Inches(0.75), Inches(1.15), Inches(6.8), Inches(1.9))
    tf_m = tx_main.text_frame
    tf_m.word_wrap = True
    p_m1 = tf_m.paragraphs[0]
    p_m1.text = "HoneyForge"
    p_m1.font.name = FONT_TITLE
    p_m1.font.size = Pt(48)
    p_m1.font.bold = True
    p_m1.font.color.rgb = COLOR_AMBER_BRIGHT

    p_m2 = tf_m.add_paragraph()
    p_m2.text = "Платформа активной кибердецепции и Threat Intelligence для корпоративного SOC"
    p_m2.font.name = FONT_TITLE
    p_m2.font.size = Pt(13.5)
    p_m2.font.color.rgb = COLOR_WHITE
    p_m2.space_before = Pt(6)

    # Team Card («самсунг» - 4 человека с ролями)
    card_team = s1.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(3.3), Inches(6.7), Inches(3.6))
    card_team.fill.solid()
    card_team.fill.fore_color.rgb = COLOR_CARD
    card_team.line.color.rgb = COLOR_BORDER
    card_team.line.width = Pt(1)

    tx_team = s1.shapes.add_textbox(Inches(1.05), Inches(3.45), Inches(6.2), Inches(3.3))
    tf_team = tx_team.text_frame
    tf_team.word_wrap = True
    tf_team.margin_left = tf_team.margin_right = tf_team.margin_top = tf_team.margin_bottom = 0

    p_team_title = tf_team.paragraphs[0]
    p_team_title.text = "Решение представлено командой «самсунг»"
    p_team_title.font.name = FONT_TITLE
    p_team_title.font.size = Pt(13.5)
    p_team_title.font.bold = True
    p_team_title.font.color.rgb = COLOR_CYAN
    p_team_title.space_after = Pt(10)

    team_members = [
        ("Фирсов Игорь (капитан)", "Архитектура C2 ядра, Anti-detection и Скрытность ловушек", COLOR_AMBER_BRIGHT),
        ("Чекаленко Александр", "Frontend-разработчик / Cyber SOC Dashboard & UI/UX", COLOR_WHITE),
        ("Попельнухин Георгий", "Data Engineer / СУБД PostgreSQL, Буферизация и Хранение событий", COLOR_WHITE),
        ("Бауэр Евгений", "DevSecOps / Docker-оркестрация и Сетевая изоляция периметров", COLOR_WHITE),
    ]

    for name, role, name_color in team_members:
        p_name = tf_team.add_paragraph()
        p_name.text = f"• {name}"
        p_name.font.name = FONT_TITLE
        p_name.font.size = Pt(11)
        p_name.font.bold = True
        p_name.font.color.rgb = name_color

        p_role = tf_team.add_paragraph()
        p_role.text = f"   Роль: {role}"
        p_role.font.name = FONT_BODY
        p_role.font.size = Pt(9.5)
        p_role.font.color.rgb = COLOR_GRAY
        p_role.space_after = Pt(6)

    # Right Side: Prominent QR Code Card for Jury
    qr_card = s1.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(7.8), Inches(1.15), Inches(4.7), Inches(5.75))
    qr_card.fill.solid()
    qr_card.fill.fore_color.rgb = COLOR_CARD_DARK
    qr_card.line.color.rgb = COLOR_AMBER
    qr_card.line.width = Pt(1.5)

    # QR Card Title
    tx_qrt = s1.shapes.add_textbox(Inches(8.0), Inches(1.35), Inches(4.3), Inches(0.6))
    tf_qrt = tx_qrt.text_frame
    tf_qrt.word_wrap = True
    p_qrt = tf_qrt.paragraphs[0]
    p_qrt.text = "Подключение жюри к стенду"
    p_qrt.font.name = FONT_TITLE
    p_qrt.font.size = Pt(15)
    p_qrt.font.bold = True
    p_qrt.font.color.rgb = COLOR_AMBER_BRIGHT
    p_qrt.alignment = PP_ALIGN.CENTER

    p_qrs = tf_qrt.add_paragraph()
    p_qrs.text = "Наведите камеру смартфона для мгновенного входа:"
    p_qrs.font.name = FONT_BODY
    p_qrs.font.size = Pt(10)
    p_qrs.font.color.rgb = COLOR_GRAY
    p_qrs.alignment = PP_ALIGN.CENTER

    # White container for QR Code
    qr_box = s1.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(8.8), Inches(2.15), Inches(2.7), Inches(2.7))
    qr_box.fill.solid()
    qr_box.fill.fore_color.rgb = RGBColor(255, 255, 255)
    qr_box.line.color.rgb = COLOR_WHITE
    qr_box.line.width = Pt(1)

    qr_path = os.path.join(ASSETS_DIR, "jury_qr_code.png")
    if os.path.exists(qr_path):
        s1.shapes.add_picture(qr_path, Inches(8.95), Inches(2.3), width=Inches(2.4), height=Inches(2.4))

    # Badge: 1-Click Демо-доступ
    b_demo = s1.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(8.2), Inches(5.05), Inches(3.9), Inches(0.38))
    b_demo.fill.solid()
    b_demo.fill.fore_color.rgb = RGBColor(17, 35, 56)
    b_demo.line.color.rgb = COLOR_CYAN
    b_demo.line.width = Pt(1)
    tf_bd = b_demo.text_frame
    p_bd = tf_bd.paragraphs[0]
    p_bd.text = "👁️ 1-Click Демо-доступ (Без ввода пароля)"
    p_bd.font.name = FONT_CODE
    p_bd.font.size = Pt(9.5)
    p_bd.font.bold = True
    p_bd.font.color.rgb = COLOR_CYAN
    p_bd.alignment = PP_ALIGN.CENTER

    # Direct URL below
    tx_url = s1.shapes.add_textbox(Inches(8.0), Inches(5.55), Inches(4.3), Inches(1.1))
    tf_url = tx_url.text_frame
    tf_url.word_wrap = True
    p_url1 = tf_url.paragraphs[0]
    p_url1.text = "Ссылка для браузера:"
    p_url1.font.name = FONT_BODY
    p_url1.font.size = Pt(9.5)
    p_url1.font.color.rgb = COLOR_GRAY
    p_url1.alignment = PP_ALIGN.CENTER

    p_url2 = tf_url.add_paragraph()
    p_url2.text = "million-heights-nursing-loud.trycloudflare.com"
    p_url2.font.name = FONT_CODE
    p_url2.font.size = Pt(8.5)
    p_url2.font.color.rgb = COLOR_WHITE
    p_url2.alignment = PP_ALIGN.CENTER

    p_url3 = tf_url.add_paragraph()
    p_url3.text = "Режим: Просмотр событий, парка ловушек и аналитики"
    p_url3.font.name = FONT_BODY
    p_url3.font.size = Pt(8.5)
    p_url3.font.color.rgb = COLOR_GREEN
    p_url3.alignment = PP_ALIGN.CENTER

    s1.notes_slide.notes_text_frame.text = (
        "СЛАЙД 1: ВСТУПЛЕНИЕ И КОМАНДА\n"
        "РЕЧЬ ДОКЛАДЧИКА:\n"
        "«Добрый день, уважаемые члены жюри и эксперты! Меня зовут Фирсов Игорь, капитан команды «самсунг».\n"
        "Мы разработали платформу HoneyForge — систему активной кибердецепции и Threat Intelligence для корпоративного SOC.\n"
        "Справа на слайде размещен QR-код: вы можете отсканировать его прямо сейчас со смартфона и без ввода пароля попасть в живой демо-стенд HoneyForge, чтобы отслеживать работу платформы в реальном времени параллельно с защитой.\n"
        "Перейдем к сути проблемы и концепции решения!»"
    )

    # ==========================================
    # SLIDE 2: ПРОБЛЕМА И КОНЦЕПЦИЯ
    # ==========================================
    s2 = prs.slides.add_slide(blank_layout)
    set_slide_background(s2)
    add_header(s2, "Концепция и Ценность", "Проблема обнаружения и подход HoneyForge", 
               "Почему традиционные SIEM/EDR слепы к скрытным атакам и как Deception решает эту задачу")

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
        "СЛАЙД 2: ПРОБЛЕМА И КОНЦЕПЦИЯ\n"
        "РЕЧЬ ДОКЛАДЧИКА:\n"
        "«В чем главная боль современного SOC? Команды реагирования перегружены тысячами событий из SIEM и EDR. "
        "Среди шума критические атаки теряются, а злоумышленники месяцами перемещаются по сети, используя легитимные учетки.\n"
        "HoneyForge решает эту проблему в корне через принцип Zero False Positives. "
        "В нашей системе ловушки и цифровые приманки мимикрируют под реальные сервисы компании: SSH-серверы, базы данных, API и токены в репозиториях. "
        "Сотрудникам они не нужны, поэтому любое касание приманки — это гарантированный инцидент 100% достоверности. Аналитик сразу начинает расследование!»"
    )

    # ==========================================
    # SLIDE 3: АРХИТЕКТУРА И СТЕК
    # ==========================================
    s3 = prs.slides.add_slide(blank_layout)
    set_slide_background(s3)
    add_header(s3, "Архитектура & Stealth", "Бескомпромиссная изоляция и Технологический стек",
               "Zero-Trust разделение контуров DMZ и Management, маскировка под RUM-телеметрию и системные демоны")

    add_card(s3, 0.8, 1.75, 5.3, 2.55, "Архитектурная безопасность (Stealth & Isolation)", [
        "Строгое разделение сетей: sysmon_internal_dmz (ловушки) vs sysmon_internal_mgmt (ядро)",
        "Нулевой доступ к БД из ловушек: атакованный агент физически изолирован от ядра",
        "Маскировка телеметрии: агент шлет события на Edge Nginx под видом /cdn-cgi/rum",
        "Мимикрия демонов: процессы работают под именами rsyslogd и systemd-resolved"
    ], COLOR_CYAN)

    add_card(s3, 0.8, 4.45, 5.3, 2.45, "Технологический стек платформы", [
        "Backend: Python 3.11, FastAPI (async), SQLAlchemy 2.0, Pydantic v2",
        "База данных & KeyStore: PostgreSQL 15, AES-256-GCM + PBKDF2 (100,000 итераций)",
        "Edge & Gateway: Двойной Nginx Reverse Proxy, Server-Sent Events (SSE)",
        "Тестирование: Pytest (22/22), 11/11 проверок скрытности (Stealth Realism Audit)"
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
    p_mg2.text = "• HoneyForge Core C2 (FastAPI async + Event Bus + WebSocket/SSE Broadcast)\n• PostgreSQL 15: изоляция схем, аудит, IoC-хранилище\n• Cryptographic KeyStore: PBKDF2-HMAC-SHA256 + AES-256-GCM\n• Доступ операторов SOC: HTTPS / mTLS, 6 ролей (RBAC)"
    p_mg2.font.name = FONT_BODY
    p_mg2.font.size = Pt(8.5)
    p_mg2.font.color.rgb = COLOR_WHITE

    s3.notes_slide.notes_text_frame.text = (
        "СЛАЙД 3: АРХИТЕКТУРА И СТЕК\n"
        "РЕЧЬ ДОКЛАДЧИКА:\n"
        "«Ключевой фактор успешной ловушки — чтобы атакующий ни на секунду не догадался, что он находится в песочнице.\n"
        "На диаграмме справа показана наша архитектура изоляции. Внутри контейнеров процессы имитируют стандартные системные демоны Linux — rsyslogd и systemd-resolved. "
        "Телеметрия с ловушки передается через Edge-прокси под видом обычного трафика мониторинга производительности Cloudflare RUM по пути /cdn-cgi/rum с HMAC-подписью.\n"
        "При этом соблюден строжайший принцип Zero-Trust: сеть ловушек DMZ полностью изолирована от управляющего ядра и базы данных. Даже если хакер получит root в ловушке, он физически не сможет обратиться к БД или ядру платформы.\n"
        "Backend платформы построен на асинхронном FastAPI и PostgreSQL с криптографическим KeyStore на базе AES-256-GCM!»"
    )

    # ==========================================
    # SLIDE 4: КОНСТРУКТОР ПРОФИЛЕЙ И 1-CLICK ДЕПЛОЙ
    # ==========================================
    s4 = prs.slides.add_slide(blank_layout)
    set_slide_background(s4)
    add_header(s4, "Конструктор Профилей & Деплой", "Конструктор профилей и Управление парком ловушек",
               "Настройка реалистичной личности сервера (Persona) и автоматическая генерация манифестов запуска")

    add_card(s4, 0.8, 1.75, 5.4, 2.55, "Конструктор цифровой личности (Persona)", [
        "Гибкие профили интерактивности: Low-Interaction (TCP tarpit) и Medium (Fake Shell)",
        "Параметры реализма: эмуляция Ubuntu 22.04 LTS, версии ядра Linux, uptime и хостнеймы",
        "Аутентичные баннеры: согласованные версии OpenSSH 8.9p1, Apache 2.4.52, Redis 7.0",
        "Приманочные учетные записи (decoy credentials) для перехвата словарей брутфорса"
    ], COLOR_AMBER)

    add_card(s4, 0.8, 4.45, 5.4, 2.45, "1-Click Автоматический Деплой", [
        "Генерация docker-compose.yml с готовой привязкой портов и маппингом сетей",
        "Генерация bash / curl однострочников для моментального деплоя в Linux",
        "Генерация PowerShell скриптов для Windows инфраструктуры",
        "Автоматическая деривация уникального HMAC-токена агента (NODE_KEY) на лету"
    ], COLOR_CYAN)

    add_image_panel(s4, 6.5, 1.75, 6.0, 5.15, "05_profile_modal.png", "Конструктор профиля ловушки: сервисы, приманки, маскировка и параметры Persona", COLOR_AMBER)

    s4.notes_slide.notes_text_frame.text = (
        "СЛАЙД 4: КОНСТРУКТОР ПРОФИЛЕЙ И ДЕПЛОЙ\n"
        "РЕЧЬ ДОКЛАДЧИКА:\n"
        "«На этом слайде показан наш конструктор профилей.\n"
        "Оператор может настроить полную цифровую личность сервера: операционную систему, версию ядра Linux, эмулируемые сервисы (SSH, HTTP, Redis, FTP, Telnet) и приманочные пароли.\n"
        "При нажатии кнопки 'Развернуть' платформа автоматически генерирует готовый Docker Compose файл, bash-скрипт или команду PowerShell со встроенным криптографическим ключом узла.\n"
        "Оператору достаточно скопировать команду и выполнить ее на любом сервере компании!»"
    )

    # ==========================================
    # SLIDE 5: СКРИНКАСТ / GIF СОЗДАНИЯ ЛОВУШКИ
    # ==========================================
    s5 = prs.slides.add_slide(blank_layout)
    set_slide_background(s5)
    add_header(s5, "Скринкаст & Демо", "Скринкаст: Процесс создания и активации ловушки",
               "Анимированная демонстрация полного цикла: от настройки профиля в конструкторе до регистрации в кластере")

    add_card(s5, 0.8, 1.75, 5.4, 1.6, "1. Настройка профиля в конструкторе", [
        "Выбор уровня: Low (Port probe/Tarpit) или Medium (Shell emulator)",
        "Привязка сетевых сервисов: SSH (порт 2222), HTTP/API (порт 8088)",
        "Маскировка под системные демоны ОС: rsyslogd / systemd-resolved"
    ], COLOR_CYAN)

    add_card(s5, 0.8, 3.45, 5.4, 1.6, "2. Выпуск криптографических ключей", [
        "Мгновенная генерация уникального NODE_KEY и HMAC-секрета телеметрии",
        "Шифрование секрета в локальном KeyStore алгоритмом AES-256-GCM",
        "Безопасная доставка в деплой-команду без раскрытия мастер-паролей"
    ], COLOR_AMBER)

    add_card(s5, 0.8, 5.15, 5.4, 1.75, "3. Активация и мониторинг Live", [
        "Выполнение команды на целевом сервере в 1 клик",
        "Мгновенная регистрация на Edge-шлюзе телеметрии",
        "Переход в статус Online и появление в оперативной консоли SOC"
    ], COLOR_GREEN)

    # Animated screencast GIF
    add_image_panel(s5, 6.5, 1.75, 6.0, 5.15, "trap_workflow.gif", "Скринкаст создания и развертывания ловушки (Анимация)", COLOR_GREEN)

    s5.notes_slide.notes_text_frame.text = (
        "СЛАЙД 5: СКРИНКАСТ СОЗДАНИЯ ЛОВУШКИ\n"
        "РЕЧЬ ДОКЛАДЧИКА:\n"
        "«Перед вами скринкаст, наглядно демонстрирующий полный цикл создания ловушки в живом интерфейсе HoneyForge.\n"
        "Оператор выбирает профиль реализма, указывает имя сервиса и сохраняет настройки. "
        "В ту же секунду платформа генерирует уникальный криптографический ключ узла и предоставляет готовый деплой-манифест.\n"
        "После запуска контейнера ловушка мгновенно связывается с Edge-шлюзом телеметрии, подтверждает HMAC-подпись и загорается зеленым индикатором Online в консоли SOC. "
        "Весь процесс занимает менее минуты!»"
    )

    # ==========================================
    # SLIDE 6: ИНТЕРАКТИВНЫЕ СЕССИИ И ПЕРЕХВАТ MALWARE
    # ==========================================
    s6 = prs.slides.add_slide(blank_layout)
    set_slide_background(s6)
    add_header(s6, "Анализ атак & Forensics", "Интерактивные сессии и Перехват вредоносного ПО",
               "Полнотекстовое TTY-логирование команд хакера, безопасный карантин артефактов и хеширование SHA-256")

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
        "СЛАЙД 6: ИНТЕРАКТИВНЫЕ СЕССИИ И MALWARE\n"
        "РЕЧЬ ДОКЛАДЧИКА:\n"
        "«Что происходит, когда хакер подключается к нашей ловушке? Перед вами реальный пример перехвата сессии.\n"
        "HoneyForge в реальном времени ведет полнотекстовое TTY-логирование каждого действия злоумышленника: вы видите, как он выполняет команду whoami, затем скачивает вредоносный дроппер через curl, делает его исполняемым и пытается запустить.\n"
        "Система автоматически перехватывает этот бинарный файл, помещает его в защищенный карантин и прямо на лету рассчитывает криптографический хеш SHA-256. "
        "Аналитик SOC получает готовый артефакт для форензики, который можно мгновенно отправить в песочницу или сверить с базами Threat Intelligence!»"
    )

    # ==========================================
    # SLIDE 7: HONEYTOKENS (ЦИФРОВЫЕ ПРИМАНКИ)
    # ==========================================
    s7 = prs.slides.add_slide(blank_layout)
    set_slide_background(s7)
    add_header(s7, "Honeytokens & Декорации", "Цифровые приманки и Корреляция скрытых угроз",
               "Размещение фиктивных секретов в коде, базах данных и на хостах для мгновенного обнаружения утечек")

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
        "СЛАЙД 7: HONEYTOKENS\n"
        "РЕЧЬ ДОКЛАДЧИКА:\n"
        "«Помимо сетевых ловушек, HoneyForge включает продвинутую подсистему Honeytokens — цифровых приманок.\n"
        "Мы генерируем реалистичные секреты и 'подбрасываем' их в корпоративные репозитории, конфигурационные файлы .env, резервные копии и историю терминалов. "
        "В системе представлены 3 ключевых типа приманок: поддельные ключи AWS IAM, учетные данные сервисных баз данных и приватные SSH-ключи для деплоя.\n"
        "Если внешний злоумышленник или инсайдер находит такой ключ и пробует использовать его, HoneyForge мгновенно генерирует алерт наивысшего приоритета CRITICAL. "
        "Это позволяет остановить утечку на этапе разведки!»"
    )

    # ==========================================
    # SLIDE 8: THREAT INTELLIGENCE & SIEM ЭКСПОРТ
    # ==========================================
    s8 = prs.slides.add_slide(blank_layout)
    set_slide_background(s8)
    add_header(s8, "Интеграция & Threat Intelligence", "Индикаторы компрометации (IoC) и Экспорт в SIEM",
               "Автоматическая выгрузка улик в стандарте STIX 2.1 JSON и CSV для мгновенной интеграции с MaxPatrol, KUMA и Splunk")

    add_card(s8, 0.8, 1.75, 5.4, 2.55, "Обогащение SOC данными Threat Intelligence", [
        "Сбор ключевых IOC: IP атакующего, User-Agent, порты, хеши файлов (SHA-256)",
        "Гранулярные уровни опасности: Critical, High, Medium, Low с детальным описанием вектора",
        "Очередь инцидентов с функцией 'Принять все' и подтверждением отработки аналитиком",
        "Реактивные события: доставка алертов в браузер дежурного оператора без задержек"
    ], COLOR_CYAN)

    add_card(s8, 0.8, 4.45, 5.4, 2.45, "Экспорт по индустриальным стандартам", [
        "STIX 2.1 JSON: международный стандарт обмена киберразведкой (OASIS Standard)",
        "Прямой импорт в SIEM/SOAR: MaxPatrol SIEM, Kaspersky KUMA, Splunk, OpenCTI, MISP",
        "CSV Экспорт: табличная выгрузка для оперативных отчетов руководству и комплаенс",
        "Интеграция с NGFW / WAF: возможность автоматической блокировки IP злоумышленника"
    ], COLOR_GREEN)

    add_image_panel(s8, 6.5, 1.75, 6.0, 5.15, "09_alerts_and_ioc.png", "Таблица IoC и панель оповещений с 1-Click экспортом STIX 2.1 и CSV", COLOR_CYAN)

    s8.notes_slide.notes_text_frame.text = (
        "СЛАЙД 8: THREAT INTELLIGENCE И SIEM\n"
        "РЕЧЬ ДОКЛАДЧИКА:\n"
        "«Любая система безопасности ценна тем, насколько бесшовно она встраивается в существующий процесс SOC.\n"
        "HoneyForge автоматически консолидирует все собранные улики в структурированную таблицу индикаторов компрометации (IoC): IP-адреса, User-Agent, атакованные учетные записи и хеши пейлоадов.\n"
        "Мы реализовали экспорт в стандарт STIX 2.1 JSON — это международный формат обмена киберразведкой, поддерживаемый ведущими российскими и зарубежными SIEM/SOAR системами, включая MaxPatrol SIEM, Kaspersky KUMA, OpenCTI и Splunk. "
        "Аналитик может в один клик выгрузить STIX 2.1 бандл или CSV-отчет!»"
    )

    # ==========================================
    # SLIDE 9: БЕЗОПАСНОСТЬ: RBAC И CRYPTO KEYSTORE
    # ==========================================
    s9 = prs.slides.add_slide(blank_layout)
    set_slide_background(s9)
    add_header(s9, "Безопасность Платформы", "Ролевая модель доступа (RBAC) и Crypto KeyStore",
               "6 ролей для команды SOC в соответствии со стандартами Enterprise и защита криптографических ключей узлов")

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
        "Изоляция учетных данных операторов: безопасное хеширование паролей PBKDF2-HMAC-SHA256"
    ], COLOR_AMBER)

    add_image_panel(s9, 6.5, 1.75, 6.0, 5.15, "10_users_and_keystore.png", "Управление операторами SOC и защищенный криптографический KeyStore", COLOR_BORDER)

    s9.notes_slide.notes_text_frame.text = (
        "СЛАЙД 9: БЕЗОПАСНОСТЬ ПЛАТФОРМЫ\n"
        "РЕЧЬ ДОКЛАДЧИКА:\n"
        "«Платформа кибердецепции сама по себе является критическим элементом инфраструктуры, поэтому требования к ее внутренней безопасности максимальны.\n"
        "В HoneyForge реализована полноценная ролевая модель доступа из 6 гранулярных ролей: от CISO и руководителя смены SOC до аналитиков L2, дежурных L1 и внешних аудиторов ИБ. "
        "Каждое действие логируется, а права строго разграничены.\n"
        "Все секреты платформы — ключи регистрации ловушек NODE_KEY, HMAC-токены телеметрии и токены приманок — защищены встроенным криптографическим KeyStore на базе AES-256-GCM с деривацией ключа через PBKDF2 со ста тысячами итераций!»"
    )

    # ==========================================
    # SLIDE 10: ИТОГИ, ПУБЛИЧНЫЙ СТЕНД И Q&A
    # ==========================================
    s10 = prs.slides.add_slide(blank_layout)
    set_slide_background(s10)
    add_header(s10, "Результаты & Q&A", "Итоги реализации и готовность к внедрению",
               "Полное соответствие требованиям ТЗ, развернутый стенд и готовность к вопросам жюри")

    add_card(s10, 0.8, 1.75, 5.4, 2.55, "Ключевые достижения проекта", [
        "100% требований кейса «Мадригал» полностью реализовано и протестировано",
        "22/22 Pytest тестов пройдено (Auth, RBAC, Realism, Sessions, Keystore)",
        "11/11 проверок скрытности (Stealth Realism Audit: DMZ, RUM, rsyslogd)",
        "Готовность к промышленной эксплуатации: 0 ложных срабатываний, STIX 2.1"
    ], COLOR_GREEN)

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
        "Публичный URL: https://million-heights-nursing-loud.trycloudflare.com",
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
    p_qa2.font.color.rgb = COLOR_WHITE
    p_qa2.alignment = PP_ALIGN.CENTER

    # Right bottom: QR Code Card on Slide 10
    s10_qr_card = s10.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.5), Inches(3.4), Inches(6.0), Inches(3.5))
    s10_qr_card.fill.solid()
    s10_qr_card.fill.fore_color.rgb = COLOR_CARD
    s10_qr_card.line.color.rgb = COLOR_BORDER
    s10_qr_card.line.width = Pt(1)

    # White box for QR code
    qr_box10 = s10.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.75), Inches(3.6), Inches(3.1), Inches(3.1))
    qr_box10.fill.solid()
    qr_box10.fill.fore_color.rgb = RGBColor(255, 255, 255)
    qr_box10.line.color.rgb = COLOR_WHITE
    qr_box10.line.width = Pt(1)

    if os.path.exists(qr_path):
        s10.shapes.add_picture(qr_path, Inches(6.85), Inches(3.7), width=Inches(2.9), height=Inches(2.9))

    tx_s10_qr = s10.shapes.add_textbox(Inches(10.0), Inches(3.8), Inches(2.35), Inches(2.7))
    tf_s10 = tx_s10_qr.text_frame
    tf_s10.word_wrap = True
    tf_s10.margin_left = tf_s10.margin_right = tf_s10.margin_top = tf_s10.margin_bottom = 0

    p_s10_1 = tf_s10.paragraphs[0]
    p_s10_1.text = "QR-код стенда"
    p_s10_1.font.name = FONT_TITLE
    p_s10_1.font.size = Pt(13)
    p_s10_1.font.bold = True
    p_s10_1.font.color.rgb = COLOR_AMBER_BRIGHT
    p_s10_1.space_after = Pt(6)

    p_s10_2 = tf_s10.add_paragraph()
    p_s10_2.text = "Мгновенный переход в консоль SOC без авторизации."
    p_s10_2.font.name = FONT_BODY
    p_s10_2.font.size = Pt(9.5)
    p_s10_2.font.color.rgb = COLOR_WHITE
    p_s10_2.space_after = Pt(8)

    p_s10_3 = tf_s10.add_paragraph()
    p_s10_3.text = "⚡ Проверка работы всех 4 активных ловушек в реальном времени."
    p_s10_3.font.name = FONT_BODY
    p_s10_3.font.size = Pt(9)
    p_s10_3.font.color.rgb = COLOR_CYAN

    s10.notes_slide.notes_text_frame.text = (
        "СЛАЙД 10: ИТОГИ И ОТВЕТЫ НА ВОПРОСЫ\n"
        "РЕЧЬ ДОКЛАДЧИКА:\n"
        "«Подводя итоги: HoneyForge полностью решает задачи кейса «Мадригал». "
        "Все 100% требований ТЗ выполнены, код покрыт тестами на 100%, архитектура обеспечивает бескомпромиссную изоляцию и нулевой уровень ложных срабатываний.\n"
        "Стенд доступен онлайн — вы можете проверить его прямо сейчас по QR-коду.\n"
        "Спасибо за внимание! Я готов ответить на любые вопросы экспертов!»"
    )

    prs.save(OUTPUT_FILE)
    print(f"[OK] Presentation successfully generated at: {OUTPUT_FILE}")


if __name__ == "__main__":
    build_deck()
