"""
SecuraPay — Demo Fintech Application
A realistic payment processing app with intentional security vulnerabilities
for Secuarden governance demo purposes.

⚠️  THIS APPLICATION CONTAINS INTENTIONAL SECURITY VULNERABILITIES.
    DO NOT deploy to production. For demo/testing use only.
"""

from flask import Flask, jsonify
from config import Config
from payments import payments_bp
from auth import auth_bp
from callbacks import callbacks_bp
from webhooks import webhooks_bp
from healthcheck import healthcheck_bp
from admin import admin_bp
from users import users_bp

app = Flask(__name__)
app.config.from_object(Config)

# Register blueprints
app.register_blueprint(payments_bp, url_prefix="/api/payments")
app.register_blueprint(auth_bp, url_prefix="/api/auth")
app.register_blueprint(callbacks_bp, url_prefix="/api/callbacks")
app.register_blueprint(webhooks_bp, url_prefix="/api/webhooks")
app.register_blueprint(healthcheck_bp, url_prefix="/api/health")
app.register_blueprint(admin_bp, url_prefix="/api/admin")
app.register_blueprint(users_bp, url_prefix="/api/users")


@app.route("/")
def index():
    return jsonify({
        "service": "SecuraPay API",
        "version": "2.4.1",
        "status": "operational"
    })


if __name__ == "__main__":
    
    app.run(host="0.0.0.0", port=5000, debug=True)
