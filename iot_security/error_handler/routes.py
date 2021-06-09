from flask import render_template

def handle_error_404(e):
    return render_template('error_handler/error_404.html'), 404


def handle_error_500(e):
    return render_template('error_handler/error_500.html'), 500

def handle_error_429(e):
    return render_template('error_handler/error_429.html'), 429