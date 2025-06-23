from flask import Flask
from flask_cors import CORS

def create_app():
    app = Flask(__name__)
    
    CORS(app)
    
    from .routes.network import network_bp
    from .routes.health import health_bp
    
    app.register_blueprint(blueprint=network_bp, url_prefix="/api/network")
    app.register_blueprint(blueprint=health_bp, url_prefix="/api/health")
    
    return app