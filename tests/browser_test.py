"""Test headless Playwright du frontend BLACKOUT WATCH.
Assemble un _site/ temporaire (comme le fait le workflow GitHub Actions)
puis sert via http.server et teste avec Chromium headless.
"""
import asyncio
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from playwright.async_api import async_playwright

BASE = Path(__file__).parent.parent
SITE_ORIG = BASE / "site"
DATA_DIR = BASE / "data"
DEMO_DIR = BASE / "demo"
SITE_TMP = BASE / "_site_test"


def assemble_site():
    """Copie site/ + data/ + demo/ dans _site_test/ (miroir de la CI)."""
    if SITE_TMP.exists():
        shutil.rmtree(SITE_TMP)
    shutil.copytree(SITE_ORIG, SITE_TMP)
    shutil.copytree(DATA_DIR, SITE_TMP / "data")
    shutil.copytree(DEMO_DIR, SITE_TMP / "demo")


def teardown_site():
    if SITE_TMP.exists():
        shutil.rmtree(SITE_TMP)


def start_server(port: int) -> subprocess.Popen:
    srv = subprocess.Popen(
        [sys.executable, "-m", "http.server", str(port)],
        cwd=str(SITE_TMP),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1)
    return srv


async def run_test_desktop(context, base_url: str) -> dict[str, bool | str | list]:
    """Tests desktop : sans et avec ?demo=1."""
    results = {}

    # ---- TEST 1 : sans ?demo=1 (data/ vide — état initial neutre) ----
    print("=== TEST 1 : sans ?demo=1 (data/ neutre) ===")
    errors1 = []
    page1 = await context.new_page()
    page1.on("console", lambda msg: errors1.append(f"[{msg.type}] {msg.text}")
              if msg.type in ("error", "warning") else None)

    resp1 = await page1.goto(base_url, wait_until="domcontentloaded")
    print(f"HTTP status        : {resp1.status}")
    await asyncio.sleep(1)

    demo_el = await page1.query_selector("#demo-banner")
    demo_vis = await demo_el.is_visible() if demo_el else False
    print(f"Bandeau demo       : {demo_vis}  (attendu: False)")
    results["t1_demo_banner"] = not demo_vis

    stale_el = await page1.query_selector("#stale-banner")
    stale_vis = await stale_el.is_visible() if stale_el else False
    print(f"Bandeau stale      : {stale_vis}  (attendu: True — data/ a generated_at=1970)")

    gs = await page1.query_selector("#global-score")
    gs_text = await gs.inner_text() if gs else "NOT FOUND"
    print(f"#global-score text : '{gs_text}'")

    zone_cards = await page1.query_selector_all(".zone-card")
    print(f"Zone cards         : {len(zone_cards)}")

    incidents = await page1.query_selector_all(".incident-card")
    print(f"Incident cards     : {len(incidents)}  (attendu: 0 — incidents.json vide)")
    results["t1_no_incidents"] = len(incidents) == 0

    csp1 = [e for e in errors1 if "Content Security Policy" in e or "CSP" in e]
    print(f"CSP violations     : {csp1}")
    js_errors1 = [e for e in errors1 if "[error]" in e]
    print(f"Console JS errors  : {js_errors1}")
    results["t1_no_csp"] = len(csp1) == 0
    results["t1_no_js_errors"] = len(js_errors1) == 0

    await page1.close()

    # ---- TEST 2 : avec ?demo=1 ----
    print()
    print("=== TEST 2 : avec ?demo=1 ===")
    errors2 = []
    page2 = await context.new_page()
    page2.on("console", lambda msg: errors2.append(f"[{msg.type}] {msg.text}")
              if msg.type in ("error", "warning") else None)

    resp2 = await page2.goto(f"{base_url}?demo=1", wait_until="domcontentloaded")
    print(f"HTTP status        : {resp2.status}")
    await asyncio.sleep(2)

    demo_el2 = await page2.query_selector("#demo-banner")
    demo_vis2 = await demo_el2.is_visible() if demo_el2 else False
    print(f"Bandeau demo       : {demo_vis2}  (attendu: True)")
    results["t2_demo_banner"] = demo_vis2

    zone_cards2 = await page2.query_selector_all(".zone-card")
    print(f"Zone cards         : {len(zone_cards2)}  (attendu: 5)")
    results["t2_zone_cards"] = len(zone_cards2) == 5

    cat_cards2 = await page2.query_selector_all(".category-card")
    print(f"Category cards     : {len(cat_cards2)}  (attendu: 6)")
    results["t2_cat_cards"] = len(cat_cards2) == 6

    incidents2 = await page2.query_selector_all(".incident-card")
    print(f"Incident cards     : {len(incidents2)}  (attendu: >= 5)")
    results["t2_incidents"] = len(incidents2) >= 5

    filter_cat = await page2.query_selector("#filter-category")
    print(f"Filtre catégorie   : {filter_cat is not None}  (attendu: True)")
    results["t2_filter_cat"] = filter_cat is not None

    chart_canvas = await page2.query_selector("#history-chart")
    print(f"Canvas chart       : {chart_canvas is not None}  (attendu: True)")
    results["t2_chart"] = chart_canvas is not None

    # --- Tous les filtres ---
    print()
    print("=== Filtres (sur ?demo=1) ===")
    # (filter_id, test_value, reset_value)
    for filter_id, test_value, reset_value in [
        ("filter-category", "cyber", ""),
        ("filter-severity", "3", "0"),
        ("filter-status", "confirmed", ""),
        ("filter-tier", "A", ""),
    ]:
        el = await page2.query_selector(f"#{filter_id}")
        if el:
            await page2.select_option(f"#{filter_id}", test_value)
            await asyncio.sleep(0.3)
            count = len(await page2.query_selector_all(".incident-card"))
            print(f"  {filter_id}={test_value} : {count} incident(s)")
            # Réinitialiser
            await page2.select_option(f"#{filter_id}", reset_value)
            await asyncio.sleep(0.2)
        else:
            print(f"  {filter_id} : NOT FOUND")

    # --- 4 périodes d'historique ---
    print()
    print("=== Périodes d'historique (sur ?demo=1) ===")
    for period in ["7", "30", "90", "365"]:
        btn = await page2.query_selector(f".btn-period[data-period='{period}']")
        if btn:
            await btn.click()
            await asyncio.sleep(0.5)
            pressed = await btn.get_attribute("aria-pressed")
            print(f"  Période {period}j : btn trouvé, aria-pressed={pressed}")
            results[f"t2_period_{period}"] = True
        else:
            print(f"  Période {period}j : btn NOT FOUND")
            results[f"t2_period_{period}"] = False

    # --- Fiche incident ---
    print()
    print("=== Fiche incident (sur ?demo=1) ===")
    await page2.select_option("#filter-category", "")
    await asyncio.sleep(0.3)
    incidents_fresh = await page2.query_selector_all(".incident-card")
    if incidents_fresh:
        await incidents_fresh[0].click()
        await asyncio.sleep(0.8)
        panel = await page2.query_selector("#incident-panel")
        panel_hidden = await panel.get_attribute("hidden") if panel else "NOT FOUND"
        print(f"Panel ouvert après clic  : {panel_hidden is None}  (attendu: True)")
        results["t2_panel_open"] = panel_hidden is None

        title_el = await panel.query_selector(".panel-title") if panel else None
        panel_title = await title_el.inner_text() if title_el else None
        print(f"Panel titre              : '{panel_title}'")

        fs_link = await panel.query_selector(".external-search-link") if panel else None
        fs_href = await fs_link.get_attribute("href") if fs_link else None
        print(f"Lien Freespoke           : href={str(fs_href)[:80] if fs_href else 'ABSENT'}")
        results["t2_freespoke_url"] = "/search/web?q=" in (fs_href or "")
        if fs_href and "/search/web?q=" not in fs_href:
            print(f"  ECHEC : URL attendue /search/web?q=, obtenu : {fs_href[:80]}")

        close_btn = await page2.query_selector("#panel-close")
        if close_btn:
            await close_btn.click()
            await asyncio.sleep(0.3)
            panel_hidden2 = await panel.get_attribute("hidden")
            print(f"Panel ferme après clic X : {panel_hidden2 == ''}  (attendu: True)")

    csp2 = [e for e in errors2 if "Content Security Policy" in e or "CSP" in e]
    print(f"CSP violations     : {csp2}")
    js_errors2 = [e for e in errors2 if "[error]" in e]
    print(f"Console JS errors  : {js_errors2}")
    warnings2 = [e for e in errors2 if "[warning]" in e]
    print(f"Console warnings   : {warnings2}")
    results["t2_no_csp"] = len(csp2) == 0
    results["t2_no_js_errors"] = len(js_errors2) == 0

    await page2.close()
    return results


async def run_test_mobile(context, base_url: str) -> dict[str, bool | str]:
    """Tests viewport mobile 390x844 (iPhone 14)."""
    print()
    print("=== TEST MOBILE 390x844 (iPhone 14) ===")
    errors_mob = []
    page_mob = await context.new_page()
    await page_mob.set_viewport_size({"width": 390, "height": 844})
    page_mob.on("console", lambda msg: errors_mob.append(f"[{msg.type}] {msg.text}")
                 if msg.type in ("error", "warning") else None)

    resp_mob = await page_mob.goto(f"{base_url}?demo=1", wait_until="domcontentloaded")
    print(f"HTTP status        : {resp_mob.status}")
    await asyncio.sleep(2)

    results = {}

    demo_mob = await page_mob.query_selector("#demo-banner")
    demo_vis_mob = await demo_mob.is_visible() if demo_mob else False
    print(f"Bandeau demo       : {demo_vis_mob}  (attendu: True)")
    results["mob_demo_banner"] = demo_vis_mob

    zone_mob = await page_mob.query_selector_all(".zone-card")
    print(f"Zone cards         : {len(zone_mob)}  (attendu: 5)")
    results["mob_zone_cards"] = len(zone_mob) == 5

    incidents_mob = await page_mob.query_selector_all(".incident-card")
    print(f"Incident cards     : {len(incidents_mob)}  (attendu: >= 5)")
    results["mob_incidents"] = len(incidents_mob) >= 5

    chart_mob = await page_mob.query_selector("#history-chart")
    print(f"Canvas chart       : {chart_mob is not None}  (attendu: True)")
    results["mob_chart"] = chart_mob is not None

    # Overflow horizontal (scroll inattendu sur mobile)
    scroll_w = await page_mob.evaluate("document.body.scrollWidth")
    viewport_w = 390
    print(f"scrollWidth={scroll_w} vs viewport={viewport_w} -> overflow: {scroll_w > viewport_w + 10}")
    results["mob_no_overflow"] = scroll_w <= viewport_w + 10

    csp_mob = [e for e in errors_mob if "Content Security Policy" in e or "CSP" in e]
    print(f"CSP violations     : {csp_mob}")
    js_errors_mob = [e for e in errors_mob if "[error]" in e]
    print(f"Console JS errors  : {js_errors_mob}")
    results["mob_no_csp"] = len(csp_mob) == 0
    results["mob_no_js_errors"] = len(js_errors_mob) == 0

    await page_mob.close()
    return results


async def main():
    assemble_site()
    srv = start_server(18080)

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()

            desktop_results = await run_test_desktop(context, "http://localhost:18080/")
            mobile_results = await run_test_mobile(context, "http://localhost:18080/")

            await browser.close()

        all_results = {**desktop_results, **mobile_results}
        failed = {k: v for k, v in all_results.items() if v is False}
        print()
        print(f"=== RÉSUMÉ : {len(all_results) - len(failed)}/{len(all_results)} assertions passées ===")
        if failed:
            print(f"ÉCHECS : {list(failed.keys())}")
        else:
            print("Tous les checks ont passé.")

    finally:
        srv.terminate()
        teardown_site()


if __name__ == "__main__":
    asyncio.run(main())
