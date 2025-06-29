from flask import Blueprint

from src.app.API.app.controllers.network import NetworkController

controller = NetworkController()

network_bp = Blueprint("network", __name__)

@network_bp.route("/", methods=["GET"])
def get_network():
    return controller.get_network()

@network_bp.route("/", methods=["POST"])
def post_network():
    return controller.create_network()