from plyer import notification

def send_alert(title, message, urgency="normal"):
    icon = ""
    if urgency == "critical":
        icon = "!!! "
    elif urgency == "warning":
        icon = "!! "
    else:
        icon = "i "

    notification.notify(
        title=f"HODOR - {icon}{title}",
        message=message,
        app_name="HODOR Security Agent",
        timeout=10
    )
    print(f"[BILDIRIM] {title}: {message}")

def alert_critical(message):
    send_alert("KRITIK TEHDIT", message, urgency="critical")

def alert_warning(message):
    send_alert("UYARI", message, urgency="warning")

def alert_info(message):
    send_alert("Bilgi", message, urgency="normal")

if __name__ == "__main__":
    alert_info("HODOR aktif ve gorevde!")
    alert_warning("Test uyarisi - sistem izleniyor")
    alert_critical("Test - Kritik tehdit bildirimi")
