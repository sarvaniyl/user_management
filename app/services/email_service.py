# email_service.py
from builtins import ValueError, dict, str
import logging
from settings.config import settings
from app.utils.smtp_connection import SMTPClient
from app.utils.template_manager import TemplateManager
from app.models.user_model import User

# Set up logging
logger = logging.getLogger(__name__)

class EmailService:
    def __init__(self, template_manager: TemplateManager):
        self.smtp_client = SMTPClient(
            server=settings.smtp_server,
            port=settings.smtp_port,
            username=settings.smtp_username,
            password=settings.smtp_password
        )
        self.template_manager = template_manager

    async def send_user_email(self, user_data: dict, email_type: str):
        try:
            subject_map = {
                'email_verification': "Verify Your Account",
                'password_reset': "Password Reset Instructions",
                'account_locked': "Account Locked Notification"
            }

            if email_type not in subject_map:
                raise ValueError("Invalid email type")

            html_content = self.template_manager.render_template(email_type, **user_data)
            
            # SMTP operation enclosed in try-except
            self.smtp_client.send_email(subject_map[email_type], html_content, user_data['email'])
            logger.info(f"Email of type '{email_type}' sent successfully to {user_data['email']}")
            return True
            
        except ValueError as ve:
            logger.error(f"Value error in send_user_email: {str(ve)}")
            raise
        except Exception as e:
            logger.error(f"Failed to send '{email_type}' email to {user_data.get('email', 'unknown')}: {str(e)}")
            # Depending on your application needs, you might want to re-raise or return False
            return False

    async def send_verification_email(self, user: User):
        try:
            verification_url = f"{settings.server_base_url}verify-email/{user.id}/{user.verification_token}"
            result = await self.send_user_email({
                "name": user.first_name,
                "verification_url": verification_url,
                "email": user.email
            }, 'email_verification')
            return result
        except Exception as e:
            logger.error(f"Failed to send verification email to user {user.id}: {str(e)}")
            return False