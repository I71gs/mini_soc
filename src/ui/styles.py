"""Styling and theme definitions for the Mini SOC security console."""

from src.core.events import EventSeverity

# Color Palette
COLOR_BG_DARK = "#090d16"
COLOR_BG_CARD = "#131b2e"
COLOR_BG_ELEVATED = "#1e293b"
COLOR_BORDER = "#2e3b52"
COLOR_BORDER_FOCUS = "#38bdf8"
COLOR_TEXT_PRIMARY = "#f8fafc"
COLOR_TEXT_SECONDARY = "#94a3b8"
COLOR_TEXT_MUTED = "#64748b"

COLOR_ACCENT = "#38bdf8"
COLOR_ACCENT_HOVER = "#0284c7"
COLOR_ACCENT_LIGHT = "rgba(56, 189, 248, 0.15)"

# Severity Palette
SEVERITY_COLORS = {
    EventSeverity.INFO: {
        "text": "#38bdf8",
        "bg": "rgba(56, 189, 248, 0.15)",
        "border": "#0284c7",
    },
    EventSeverity.LOW: {
        "text": "#4ade80",
        "bg": "rgba(74, 222, 128, 0.15)",
        "border": "#22c55e",
    },
    EventSeverity.MEDIUM: {
        "text": "#facc15",
        "bg": "rgba(250, 204, 21, 0.15)",
        "border": "#eab308",
    },
    EventSeverity.HIGH: {
        "text": "#fb923c",
        "bg": "rgba(251, 146, 60, 0.15)",
        "border": "#ea580c",
    },
    EventSeverity.CRITICAL: {
        "text": "#f87171",
        "bg": "rgba(248, 113, 113, 0.15)",
        "border": "#dc2626",
    },
}

# Status Palette for Incidents
STATUS_COLORS = {
    "open": {"text": "#f87171", "bg": "rgba(248, 113, 113, 0.15)", "border": "#dc2626"},
    "investigating": {"text": "#facc15", "bg": "rgba(250, 204, 21, 0.15)", "border": "#eab308"},
    "mitigated": {"text": "#38bdf8", "bg": "rgba(56, 189, 248, 0.15)", "border": "#0284c7"},
    "resolved": {"text": "#4ade80", "bg": "rgba(74, 222, 128, 0.15)", "border": "#22c55e"},
}

GLOBAL_STYLESHEET = f"""
QMainWindow, QDialog {{
    background-color: {COLOR_BG_DARK};
    color: {COLOR_TEXT_PRIMARY};
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    font-size: 13px;
}}

QWidget {{
    color: {COLOR_TEXT_PRIMARY};
}}

/* Sidebar navigation */
#sidebar {{
    background-color: {COLOR_BG_CARD};
    border-right: 1px solid {COLOR_BORDER};
    min-width: 200px;
    max-width: 200px;
}}

#sidebar QPushButton {{
    background-color: transparent;
    color: {COLOR_TEXT_SECONDARY};
    border: none;
    border-radius: 6px;
    padding: 10px 14px;
    text-align: left;
    font-weight: 500;
    font-size: 13px;
}}

#sidebar QPushButton:hover {{
    background-color: {COLOR_BG_ELEVATED};
    color: {COLOR_TEXT_PRIMARY};
}}

#sidebar QPushButton:checked {{
    background-color: {COLOR_ACCENT_LIGHT};
    color: {COLOR_ACCENT};
    font-weight: bold;
    border-left: 3px solid {COLOR_ACCENT};
}}

/* Header Bar */
#headerBar {{
    background-color: {COLOR_BG_CARD};
    border-bottom: 1px solid {COLOR_BORDER};
    padding: 8px 16px;
}}

/* Top Status Cards */
#statusCard {{
    background-color: {COLOR_BG_CARD};
    border: 1px solid {COLOR_BORDER};
    border-radius: 8px;
    padding: 12px;
}}

#statusCard:hover {{
    border: 1px solid {COLOR_BORDER_FOCUS};
}}

/* Tables */
QTableWidget {{
    background-color: {COLOR_BG_CARD};
    border: 1px solid {COLOR_BORDER};
    border-radius: 8px;
    gridline-color: #1a253a;
    selection-background-color: #27354f;
    selection-color: {COLOR_TEXT_PRIMARY};
    font-size: 12px;
}}

QHeaderView::section {{
    background-color: {COLOR_BG_ELEVATED};
    color: {COLOR_TEXT_SECONDARY};
    padding: 8px 10px;
    border: none;
    border-right: 1px solid {COLOR_BORDER};
    border-bottom: 1px solid {COLOR_BORDER};
    font-weight: 600;
    font-size: 12px;
}}

QHeaderView::section:hover {{
    color: {COLOR_TEXT_PRIMARY};
}}

/* Details Pane */
#detailsPane {{
    background-color: {COLOR_BG_CARD};
    border: 1px solid {COLOR_BORDER};
    border-radius: 8px;
    padding: 14px;
}}

/* Buttons */
QPushButton {{
    background-color: {COLOR_BG_ELEVATED};
    color: {COLOR_TEXT_PRIMARY};
    border: 1px solid {COLOR_BORDER};
    border-radius: 6px;
    padding: 6px 14px;
    font-weight: 500;
}}

QPushButton:hover {{
    background-color: #2d3b52;
    border-color: #475569;
}}

QPushButton:pressed {{
    background-color: #1a2538;
}}

QPushButton:disabled {{
    background-color: #131b28;
    color: {COLOR_TEXT_MUTED};
    border-color: #1f2a3c;
}}

QPushButton#primaryAction {{
    background-color: {COLOR_ACCENT};
    color: #030712;
    border: none;
    font-weight: 600;
}}

QPushButton#primaryAction:hover {{
    background-color: {COLOR_ACCENT_HOVER};
    color: #ffffff;
}}

/* Input controls */
QLineEdit, QComboBox {{
    background-color: {COLOR_BG_ELEVATED};
    color: {COLOR_TEXT_PRIMARY};
    border: 1px solid {COLOR_BORDER};
    border-radius: 6px;
    padding: 6px 10px;
    selection-background-color: {COLOR_ACCENT};
}}

QLineEdit:focus, QComboBox:focus {{
    border: 1px solid {COLOR_BORDER_FOCUS};
}}

QComboBox::drop-down {{
    border: none;
    width: 20px;
}}

QComboBox QAbstractItemView {{
    background-color: {COLOR_BG_ELEVATED};
    color: {COLOR_TEXT_PRIMARY};
    border: 1px solid {COLOR_BORDER};
    selection-background-color: #283750;
}}

QTextEdit, QPlainTextEdit {{
    background-color: {COLOR_BG_ELEVATED};
    color: {COLOR_TEXT_PRIMARY};
    border: 1px solid {COLOR_BORDER};
    border-radius: 6px;
    padding: 6px;
}}

/* Scroll bars */
QScrollBar:vertical {{
    background: {COLOR_BG_DARK};
    width: 10px;
    margin: 0px;
    border-radius: 5px;
}}

QScrollBar::handle:vertical {{
    background: {COLOR_BORDER};
    min-height: 20px;
    border-radius: 5px;
}}

QScrollBar::handle:vertical:hover {{
    background: #475569;
}}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}

QScrollBar:horizontal {{
    background: {COLOR_BG_DARK};
    height: 10px;
    margin: 0px;
    border-radius: 5px;
}}

QScrollBar::handle:horizontal {{
    background: {COLOR_BORDER};
    min-width: 20px;
    border-radius: 5px;
}}

QScrollBar::handle:horizontal:hover {{
    background: #475569;
}}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    width: 0px;
}}

/* Tab Bar */
QTabWidget::pane {{
    border: 1px solid {COLOR_BORDER};
    background-color: {COLOR_BG_CARD};
    border-radius: 6px;
}}

QTabBar::tab {{
    background-color: {COLOR_BG_ELEVATED};
    color: {COLOR_TEXT_SECONDARY};
    padding: 8px 16px;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
    margin-right: 2px;
}}

QTabBar::tab:selected {{
    background-color: {COLOR_BG_CARD};
    color: {COLOR_ACCENT};
    font-weight: 600;
}}
"""
