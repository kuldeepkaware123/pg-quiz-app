from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps
import json
import os

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///quiz.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    # ...existing code...
class Category(db.Model):
    # ...existing code...
class Quiz(db.Model):
    # ...existing code...
class Question(db.Model):
    # ...existing code...
class Option(db.Model):
    # ...existing code...
class Result(db.Model):
    # ...existing code...
class UserAnswer(db.Model):
    # ...existing code...
class Achievement(db.Model):
    # ...existing code...

@app.route('/register', methods=['GET', 'POST'])
def register():
    # ...existing code...
@app.route('/admin/dashboard')
@login_required
@admin_required
def dashboard():
    # ...existing code...
@app.route('/admin/upload_quiz', methods=['POST'])
@login_required
def upload_quiz():
    # ...existing code...
@app.route('/quiz/<int:quiz_id>')
@login_required
def take_quiz(quiz_id):
    # ...existing code...
@app.route('/submit_quiz/<int:quiz_id>', methods=['POST'])
@login_required
def submit_quiz(quiz_id):
    # ...existing code...
@app.route('/logout')
@login_required
def logout():
    # ...existing code...
@app.route('/admin/edit_quiz/<int:quiz_id>', methods=['GET', 'POST'])
@login_required
def edit_quiz(quiz_id):
    # ...existing code...
@app.route('/admin/delete_quiz/<int:quiz_id>', methods=['POST'])
@login_required
def delete_quiz(quiz_id):
    # ...existing code...
@app.route('/admin/create_user', methods=['POST'])
@login_required
@admin_required
def create_user():
    # ...existing code...

# Vercel requires the app to be callable as 'app'
if __name__ == "__main__":
    app.run()
