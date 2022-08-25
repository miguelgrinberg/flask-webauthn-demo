import os


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
    ALCHEMICAL_DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///app.db')

    WEBAUTHN_RP_ID = 'localhost'
    WEBAUTHN_RP_NAME = 'Flask WebAuthn Demo'
    WEBAUTHN_RP_ORIGIN = 'http://localhost:5000'
