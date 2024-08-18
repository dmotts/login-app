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
        self.users = {}  # Dictionary to simulate a user database

        # Configure logging
        self.logger = logging.getLogger(__name__)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)

        # Define routes
        self.blueprint.add_url_rule('/login', 'login', self.login, methods=['GET', 'POST'])
        self.blueprint.add_url_rule('/signup', 'signup', self.signup, methods=['GET', 'POST'])
        self.blueprint.add_url_rule('/logout', 'logout', self.logout)

    def login(self):
        """
        Handles user login. If the credentials are correct, the user is logged in and redirected to the home page.
        """
        if request.method == 'POST':
            email = request.form['signin-email']
            password = request.form['signin-password']

            user = self.users.get(email)
            if user and check_password_hash(user['password'], password):
                session['username'] = user['name']
                self.logger.info(f'User {user["name"]} logged in successfully.')
                return redirect(url_for('index'))
            else:
                flash('Invalid email or password')
                self.logger.warning(f'Failed login attempt for email: {email}')
                return redirect(url_for('auth.login'))

        return render_template('login.html')

    def signup(self):
        """
        Handles new user registration. Users must provide a unique email and matching passwords.
        """
        if request.method == 'POST':
            name = request.form['signup-name']
            email = request.form['signup-email']
            password = request.form['signup-password']

            if email in self.users:
                flash('Email already registered')
                self.logger.warning(f'Failed registration attempt for existing email: {email}')
                return redirect(url_for('auth.signup'))

            self.users[email] = {
                'name': name,
                'password': generate_password_hash(password)
            }
            flash('Registration successful! Please log in.')
            self.logger.info(f'New user registered with email: {email}')
            return redirect(url_for('auth.login'))

        return render_template('signup.html')

    def logout(self):
        """
        Logs out the current user by clearing the session.
        """
        if 'username' in session:
            self.logger.info(f'User {session["username"]} logged out.')
        session.pop('username', None)
        return redirect(url_for('auth.login'))
