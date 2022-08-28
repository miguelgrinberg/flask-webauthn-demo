import os
from flask import Flask
from alchemical.flask import Alchemical
from flask_login import LoginManager

db = Alchemical()
login = LoginManager()
login.login_view = 'auth.login'


def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
    app.config['ALCHEMICAL_DATABASE_URL'] = os.environ.get(
        'DATABASE_URL', 'sqlite:///app.db'
    )

    db.init_app(app)
    login.init_app(app)

    from . import main

    app.register_blueprint(main.bp)

    from . import auth

    app.register_blueprint(auth.bp)

    from . import webauthn

    app.register_blueprint(webauthn.bp)

    @app.cli.command()
    def create_db():
        """Create the application's database."""
        db.create_all()

    return app
