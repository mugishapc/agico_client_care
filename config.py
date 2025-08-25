import os
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'd29c234ca310aa6990092d4b6cd4c4854585c51e1f73bf4de510adca03f5bc4e'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///instance/agico_client_care.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Email configuration
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.googlemail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', '587'))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', 'on', '1']
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', MAIL_USERNAME)

    # File uploads
    UPLOADED_IMAGES_DEST = os.path.join(basedir, 'uploads', 'images')
    UPLOADED_DOCS_DEST = os.path.join(basedir, 'uploads', 'docs')
    ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    ALLOWED_DOC_EXTENSIONS = {'pdf', 'doc', 'docx'}
   
    # Admin credentials
    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL') or 'mugishapc1@gmail.com'
    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD') or '0220Mpc.'