"""Views package for Mini SOC UI."""

from src.ui.views.detections_view import DetectionsView
from src.ui.views.events_view import EventsView
from src.ui.views.incidents_view import IncidentsView
from src.ui.views.overview_view import OverviewView
from src.ui.views.settings_view import SettingsView

__all__ = [
    "DetectionsView",
    "EventsView",
    "IncidentsView",
    "OverviewView",
    "SettingsView",
]
