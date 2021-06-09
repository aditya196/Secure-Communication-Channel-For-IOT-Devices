from flask import Blueprint, render_template
from iot_security import limiter
main = Blueprint('main', __name__)


@main.route('/')
@limiter.exempt
def index():
    return render_template('main/index.html')