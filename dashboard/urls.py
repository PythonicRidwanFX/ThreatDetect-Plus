from django.urls import path
from . import views

urlpatterns = [
    path("dashboard/", views.dashboard, name="dashboard"),
    path("monitoring/", views.monitoring, name="monitoring"),
    path("detection/", views.detection, name="detection"),
    path("alerts/", views.alerts, name="alerts"),
    path("reports/", views.reports, name="reports"),
    path("settings/", views.settings, name="settings"),
    path(
        "reports/",
        views.reports,
        name="reports"
    ),


    path(
        "reports/threat/pdf/",
        views.threat_report_pdf,
        name="threat_report_pdf"
    ),


    path(
        "reports/threat/excel/",
        views.threat_report_excel,
        name="threat_report_excel"
    ),


    path(
        "reports/packet/pdf/",
        views.packet_report_pdf,
        name="packet_report_pdf"
    ),


    path(
        "reports/alert/pdf/",
        views.alert_report_pdf,
        name="alert_report_pdf"
    ),
    path(
        "reports/threat/excel/",
        views.threat_report_excel,
        name="threat_report_excel"
    ),


    path(
        "reports/alert/pdf/",
        views.alert_report_pdf,
        name="alert_report_pdf"
    ),


    path(
        "reports/alert/excel/",
        views.alert_report_excel,
        name="alert_report_excel"
    ),
    path(
    "reports/threat/excel/",
    views.threat_report_excel,
    name="threat_report_excel"
    ),

    path(
        'packet-report-excel/',
        views.packet_report_excel,
        name='packet_report_excel'
    ),
    path(
        "database-status/",
        views.database_status,
        name="database_status"
    ),
]