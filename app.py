# auth_app/app.py

import logging
from flask import Flask, render_template, session, redirect, url_for
from routes import init_app

class AuthApp:
    """
    The main application class that initializes and runs the Flask app.
    """

    def __init__(self):
        """
        Initializes the Flask app and sets up the routes and logging.
        """
        self.app = Flask(__name__)
        self.app.secret_key = 'your_secret_key'  # Replace with a real secret key in production

        # Initialize routes
        init_app(self.app)

        # Configure logging
        self.logger = logging.getLogger('auth_app')
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)

        # Add additional routes
        self.app.add_url_rule('/', 'index', self.index)

    def index(self):
        """
        The home page route. Displays a welcome message if the user is logged in.
        """
        if 'username' in session:
            self.logger.info(f'Accessed home page by user: {session["username"]}')
            return f"Hello, {session['username']}! You are logged in."
        self.logger.info('Accessed home page without being logged in.')
        return redirect(url_for('auth.login'))

    def run(self):
        """
        Runs the Flask application.
        """
        self.logger.info('Starting the Flask application.')
        self.app.run(debug=True)

if __name__ == '__main__':
    auth_app = AuthApp()
    auth_app.run()
