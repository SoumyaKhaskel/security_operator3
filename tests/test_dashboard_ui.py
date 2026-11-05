"""Static checks for the approved local dashboard design and UI safeguards."""

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class DashboardUiTests(unittest.TestCase):
    def test_required_sections_themes_fonts_and_responsive_layout_exist(self):
        html = (ROOT / "dashboard" / "index.html").read_text(encoding="utf-8")
        css = (ROOT / "dashboard" / "styles.css").read_text(encoding="utf-8")
        js = (ROOT / "dashboard" / "app.js").read_text(encoding="utf-8")

        for section in ("overview", "datasets", "investigations", "findings", "approvals", "processed", "audit", "reports", "settings"):
            self.assertIn(f'id="page-{section}"', html)
        self.assertIn("#111111", css)
        self.assertIn("#1A1A1A", css)
        self.assertIn("#F1F0EA", css)
        self.assertIn("#E8E8E1", css)
        self.assertIn('"Source Sans 3"', css)
        self.assertIn('"IBM Plex Mono"', css)
        self.assertIn("@media(max-width:760px)", css)
        self.assertIn("data-theme=\"dark\"", html)
        self.assertIn("setTheme", js)
        self.assertIn("sop-theme", js)

    def test_data_is_rendered_without_html_interpolation_and_required_controls_exist(self):
        html = (ROOT / "dashboard" / "index.html").read_text(encoding="utf-8")
        js = (ROOT / "dashboard" / "app.js").read_text(encoding="utf-8")
        icons = (ROOT / "dashboard" / "icons.svg").read_text(encoding="utf-8")

        self.assertNotIn("innerHTML", js)
        self.assertNotIn("eval(", js)
        for endpoint in ("/api/overview", "/api/datasets", "/api/investigations", "/api/findings", "/api/proposals", "/api/processed-events", "/api/audit", "/api/reports/summary", "/api/settings"):
            self.assertIn(endpoint, js)
        self.assertIn("Start Investigation", html)
        self.assertIn("aria-live=\"polite\"", html)
        self.assertIn('id="dashboard"', icons)
        self.assertIn('id="shield-check"', icons)
        self.assertIn('id="file-check"', icons)
        self.assertIn('id="chart-bar"', icons)


if __name__ == "__main__":
    unittest.main()
