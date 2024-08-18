# auth_app/routes/auth_routes.py

import logging
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash

class AuthRoutes:
    """
    A class to handle authentication routes including login, registration, and logout.
    """

    def __init__(self):
        """
        Initializes the AuthRoutes with a Flask Blueprint and in-memory user storage.
        """
        self.blueprint = Blueprint('auth', __name__)
        self.users = {}

        # Configure logging
        self.logger = logging.getLogger(__name__)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)

        # Define routes
        self.blueprint.add_url_rule('/login', 'login', self.login, methods=['GET', 'POST'])
        self.blueprint.add_url_rule('/register', 'register', self.register, methods=['GET', 'POST'])
        self.blueprint.add_url_rule('/logout', 'logout', self.logout)

    def login(self):
        """
        Handles user login. If the credentials are correct, the user is logged in and redirected to the home page.
        """
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']

            if username in self.users and check_password_hash(self.users[username], password):
                session['username'] = username
                self.logger.info(f'User {username} logged in successfully.')
                return redirect(url_for('index'))
            else:
                flash('Invalid username or password')
                self.logger.warning(f'Failed login attempt for username: {username}')
                return redirect(url_for('auth.login'))

        return render_template('login.html')

    def register(self):
        """
        Handles new user registration. Users must provide a unique username and matching passwords.
        """
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            confirm_password = request.form['confirm_password']

            if username in self.users:
                flash('Username already exists')
                self.logger.warning(f'Failed registration attempt for existing username: {username}')
                return redirect(url_for('auth.register'))

            if password != confirm_password:
                flash('Passwords do not match')
                self.logger.warning(f'Failed registration attempt due to password mismatch for username: {username}')
                return redirect(url_for('auth.register'))

            self.users[username] = generate_password_hash(password)
            flash('Registration successful! Please log in.')
            self.logger.info(f'New user registered with username: {username}')
            return redirect(url_for('auth.login'))

        return render_template('register.html')

    def logout(self):
        """
        Logs out the current user by clearing the session.
        """
        if 'username' in session:
            self.logger.info(f'User {session["username"]} logged out.')
        session.pop('username', None)
        return redirect(url_for('auth.login'))
