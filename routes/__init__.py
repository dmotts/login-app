from .auth_routes import AuthRoutes

def init_app(app):
    """
    Registers the authentication routes with the Flask application.
    """
    auth_routes = AuthRoutes()
    app.register_blueprint(auth_routes.blueprint)
