import os
import sys
import time

sys.path.insert(0, r'C:\умир\venv\Lib\site-packages')
from playwright.sync_api import sync_playwright
from PIL import Image

OUT_DIR = os.path.abspath('presentation_assets')
os.makedirs(OUT_DIR, exist_ok=True)

def capture_all():
    print("[*] Starting Playwright capture for presentation...")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            viewport={'width': 1600, 'height': 900},
            ignore_https_errors=True
        )
        page = context.new_page()

        print("[*] Navigating to https://localhost...")
        page.goto('https://localhost', wait_until='networkidle')

        # 0. Login
        page.wait_for_selector('#login-username', timeout=10000)
        page.screenshot(path=os.path.join(OUT_DIR, '00_login_screen.png'))
        page.fill('#login-username', 'admin')
        page.fill('#login-password', 'zd4maiMGqDrbARkXKbQDJQ')
        page.click('button[type="submit"]')

        # Wait for main UI
        page.wait_for_selector('#nav-tabs-bar', timeout=10000)
        page.wait_for_timeout(1500)

        # 1. Monitoring Dashboard
        print("[*] Capturing 01_dashboard.png...")
        page.click('button[data-tab="tab-live"]')
        page.wait_for_timeout(1000)
        page.screenshot(path=os.path.join(OUT_DIR, '01_dashboard.png'))

        # 2. Traps Park
        print("[*] Capturing 02_traps_park.png...")
        page.click('button[data-tab="tab-traps"]')
        page.wait_for_timeout(1000)
        page.screenshot(path=os.path.join(OUT_DIR, '02_traps_park.png'))

        # 3. Trap Deploy Modal
        print("[*] Capturing 03_trap_deploy_modal.png...")
        # open deploy modal for n-8c1b
        page.evaluate("openDeployModal('n-8c1b')")
        page.wait_for_timeout(1000)
        page.screenshot(path=os.path.join(OUT_DIR, '03_trap_deploy_modal.png'))
        page.evaluate("closeModal('modal-deploy')")
        page.wait_for_timeout(500)

        # 4. Profiles Tab
        print("[*] Capturing 04_profiles_list.png...")
        page.click('button[data-tab="tab-profiles"]')
        page.wait_for_timeout(1000)
        page.screenshot(path=os.path.join(OUT_DIR, '04_profiles_list.png'))

        # 5. Profile Builder Modal
        print("[*] Capturing 05_profile_modal.png...")
        page.evaluate("openCreateProfileModal()")
        page.wait_for_timeout(1000)
        page.screenshot(path=os.path.join(OUT_DIR, '05_profile_modal.png'))
        page.evaluate("closeModal('modal-profile')")
        page.wait_for_timeout(500)

        # 6. Interactive Sessions
        print("[*] Capturing 06_sessions.png...")
        page.click('button[data-tab="tab-sessions"]')
        page.wait_for_timeout(1000)
        page.screenshot(path=os.path.join(OUT_DIR, '06_sessions.png'))

        # 7. Session Terminal Playback Modal
        print("[*] Capturing 07_session_modal.png...")
        page.evaluate("openSessionDetails('sess-8f12a9')")
        page.wait_for_timeout(1000)
        page.screenshot(path=os.path.join(OUT_DIR, '07_session_modal.png'))
        page.evaluate("closeModal('modal-session')")
        page.wait_for_timeout(500)

        # 8. Honeytokens
        print("[*] Capturing 08_honeytokens.png...")
        page.click('button[data-tab="tab-honeytokens"]')
        page.wait_for_timeout(1000)
        page.screenshot(path=os.path.join(OUT_DIR, '08_honeytokens.png'))

        # 9. Alerts & IoC
        print("[*] Capturing 09_alerts_and_ioc.png...")
        page.click('button[data-tab="tab-alerts-ioc"]')
        page.wait_for_timeout(1000)
        page.screenshot(path=os.path.join(OUT_DIR, '09_alerts_and_ioc.png'))

        # 10. Users & KeyStore
        print("[*] Capturing 10_users_and_keystore.png...")
        page.click('button[data-tab="tab-users-keystore"]')
        page.wait_for_timeout(1000)
        page.screenshot(path=os.path.join(OUT_DIR, '10_users_and_keystore.png'))

        # 11. GIF Frames generation for Trap Creation & Live Attack
        print("[*] Capturing GIF frames...")
        gif_frames = []

        # Frame 1: Profiles tab
        page.click('button[data-tab="tab-profiles"]')
        page.wait_for_timeout(600)
        f1_path = os.path.join(OUT_DIR, 'gif_f1.png')
        page.screenshot(path=f1_path)
        gif_frames.append(Image.open(f1_path))

        # Frame 2: Register Trap modal
        page.click('button[data-tab="tab-traps"]')
        page.wait_for_timeout(600)
        page.evaluate("openRegisterTrapModal()")
        page.wait_for_timeout(600)
        f2_path = os.path.join(OUT_DIR, 'gif_f2.png')
        page.screenshot(path=f2_path)
        gif_frames.append(Image.open(f2_path))

        # Frame 3: Deploy Artifacts modal
        page.evaluate("closeModal('modal-register-trap')")
        page.evaluate("openDeployModal('n-8c1b')")
        page.wait_for_timeout(600)
        f3_path = os.path.join(OUT_DIR, 'gif_f3.png')
        page.screenshot(path=f3_path)
        gif_frames.append(Image.open(f3_path))
        page.evaluate("closeModal('modal-deploy')")

        # Frame 4: Traps table online
        page.wait_for_timeout(600)
        f4_path = os.path.join(OUT_DIR, 'gif_f4.png')
        page.screenshot(path=f4_path)
        gif_frames.append(Image.open(f4_path))

        # Frame 5: Live Monitoring Dashboard
        page.click('button[data-tab="tab-live"]')
        page.wait_for_timeout(800)
        f5_path = os.path.join(OUT_DIR, 'gif_f5.png')
        page.screenshot(path=f5_path)
        gif_frames.append(Image.open(f5_path))

        # Build GIF
        gif_out = os.path.join(OUT_DIR, 'trap_workflow.gif')
        if gif_frames:
            gif_frames[0].save(
                gif_out,
                save_all=True,
                append_images=gif_frames[1:],
                duration=1200,  # 1.2s per frame
                loop=0
            )
            print(f"[+] Animated GIF created: {gif_out}")

        browser.close()
    print("[+] All presentation screenshots captured successfully!")

if __name__ == '__main__':
    capture_all()
