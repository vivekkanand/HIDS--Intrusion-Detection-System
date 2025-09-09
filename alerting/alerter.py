import logging, requests, smtplib
from email.mime.text import MIMEText

class Alerter:
    def __init__(self, cfg, logger):
        self.cfg = cfg
        self.log = logger

    def alert(self, summary: str, details: dict, severity: str = "WARNING"):
        if self.cfg.get("console", True):
            self.log.warning(f"[ALERT:{severity}] {summary} | details={details}")

        webhook = self.cfg.get("slack_webhook", "")
        if webhook:
            try:
                requests.post(webhook, json={"text": f":rotating_light: *{severity}* {summary}\n```{details}```"} , timeout=5)
            except Exception as e:
                self.log.error(f"Slack alert failed: {e}")

        email_cfg = self.cfg.get("email", {})
        if email_cfg.get("enabled", False):
            try:
                msg = MIMEText(f"{summary}\n\n{details}")
                msg['Subject'] = f"[AI Sec Monitor] {severity}: {summary}"
                msg['From'] = email_cfg.get("from_addr")
                msg['To'] = email_cfg.get("to_addr")
                with smtplib.SMTP(email_cfg.get("smtp_host"), int(email_cfg.get("smtp_port", 587))) as server:
                    server.starttls()
                    server.login(email_cfg.get("username"), email_cfg.get("password"))
                    server.sendmail(msg['From'], [msg['To']], msg.as_string())
            except Exception as e:
                self.log.error(f"Email alert failed: {e}")
