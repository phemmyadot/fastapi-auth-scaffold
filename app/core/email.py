from email.message import EmailMessage
from pathlib import Path

import aiosmtplib
from jinja2 import Environment, FileSystemLoader

from app.core.config import settings

TEMPLATE_DIR = Path(__file__).parent.parent / "templates" / "email"
jinja_env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True)


async def send_email(to: str, subject: str, template_name: str, context: dict) -> None:
    """Send an HTML email using aiosmtplib + jinja2 template."""
    template = jinja_env.get_template(template_name)
    html_body = template.render(**context)

    message = EmailMessage()
    message["From"] = settings.EMAIL_FROM
    message["To"] = to
    message["Subject"] = subject
    message.set_content(html_body, subtype="html")

    await aiosmtplib.send(
        message,
        hostname=settings.SMTP_HOST,
        port=settings.SMTP_PORT,
        username=settings.SMTP_USER,
        password=settings.SMTP_PASSWORD,
        start_tls=True,
    )


async def send_password_reset_email(to: str, reset_token: str) -> None:
    await send_email(
        to=to,
        subject="Password Reset Request",
        template_name="password_reset.html",
        context={"reset_token": reset_token, "project_name": settings.PROJECT_NAME},
    )


async def send_verification_email(to: str, verification_token: str) -> None:
    await send_email(
        to=to,
        subject="Verify Your Email",
        template_name="email_verification.html",
        context={"verification_token": verification_token, "project_name": settings.PROJECT_NAME},
    )
