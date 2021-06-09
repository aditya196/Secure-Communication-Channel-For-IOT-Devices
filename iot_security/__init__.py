from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_mail import Mail
from iot_security.config import DevelopmentConfig
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

db = SQLAlchemy()
migrate = Migrate()
mail = Mail()
login_manager = LoginManager()
login_manager.login_message = 'Please login to continue'
login_manager.login_view = 'user.login'
login_manager.login_message_category = 'info'
limiter = Limiter(key_func=get_remote_address)

def create_app(config=DevelopmentConfig):
    app = Flask(__name__)
    app.config.from_object(config)
    db.init_app(app)
    limiter.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    login_manager.session_protection = "strong"
    mail.init_app(app)
    from iot_security.models import Iotserver
    from iot_security.models import Iotdevice
    from iot_security.models import User
    from iot_security.models import UserToken
    from iot_security.models import Admin
    from iot_security.models import AdminToken
    from iot_security.models import Metertransactionlog
    from iot_security.models import Tax
    from iot_security.models import Slablog
    from iot_security.models import Property
    from iot_security.models import Tenant
    from iot_security.models import Miscellaneous
    from iot_security.models import Billrequestdefaulters
    from iot_security.models import Billrequestpaymentdefaulters
    from iot_security.models import Supportquery
    from iot_security.auth import utils
    from iot_security.main.routes import main
    from iot_security.error_handler.routes import handle_error_404, handle_error_500, handle_error_429
    from iot_security.user.routes  import user
    from iot_security.admin.routes import admin
    from iot_security.api.routes import api
    app.register_error_handler(404, handle_error_404)
    app.register_error_handler(500, handle_error_500)
    app.register_error_handler(429, handle_error_429)
    app.register_blueprint(main)
    login_manager.blueprint_login_views = {
        'admin' : '/admin/login',
        'user' : '/user/login'
    }
    app.register_blueprint(admin,url_prefix='/admin')
    app.register_blueprint(user, url_prefix='/user')
    app.register_blueprint(api,url_prefix='/api')
    return app
