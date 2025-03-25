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
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    results = db.relationship('Result', backref='user', lazy=True)
    achievements = db.relationship('Achievement', backref='user', lazy=True)
    quiz_progress = db.relationship('QuizProgress', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(200))
    quizzes = db.relationship('Quiz', backref='category', lazy=True)

class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    duration = db.Column(db.Integer, nullable=False)  # in minutes
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))
    difficulty = db.Column(db.String(20), default='medium')  # easy, medium, hard
    passing_percentage = db.Column(db.Float, default=60.0)
    max_attempts = db.Column(db.Integer, default=1)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    questions = db.relationship('Question', backref='quiz', lazy=True)
    results = db.relationship('Result', backref='quiz', lazy=True)
    prerequisites = db.relationship('QuizPrerequisite', 
                                  backref='quiz', 
                                  lazy=True,
                                  foreign_keys='QuizPrerequisite.quiz_id',
                                  primaryjoin='Quiz.id==QuizPrerequisite.quiz_id')
    prerequisite_for = db.relationship('QuizPrerequisite',
                                     backref='prerequisite_quiz',
                                     lazy=True,
                                     foreign_keys='QuizPrerequisite.prerequisite_quiz_id',
                                     primaryjoin='Quiz.id==QuizPrerequisite.prerequisite_quiz_id')

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'))
    question_text = db.Column(db.Text, nullable=False)
    question_type = db.Column(db.String(20), nullable=False)  # multiple_choice, true_false, short_answer
    image_url = db.Column(db.String(200))
    points = db.Column(db.Integer, default=1)
    negative_marking = db.Column(db.Float, default=0.0)
    options = db.relationship('Option', backref='question', lazy=True)
    correct_answer = db.Column(db.String(500))
    explanation = db.Column(db.Text)

class Option(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'))
    text = db.Column(db.String(200), nullable=False)
    is_correct = db.Column(db.Boolean, default=False)

class Result(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    total_questions = db.Column(db.Integer, nullable=False)
    time_taken = db.Column(db.Integer)  # in seconds
    completed_at = db.Column(db.DateTime, default=datetime.utcnow)
    answers = db.relationship('UserAnswer', backref='result', lazy=True)
    status = db.Column(db.String(20), default='completed')  # completed, passed, failed

class UserAnswer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    result_id = db.Column(db.Integer, db.ForeignKey('result.id'))
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'))
    answer = db.Column(db.String(500))
    is_correct = db.Column(db.Boolean)
    points_earned = db.Column(db.Float)

class Achievement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    earned_at = db.Column(db.DateTime, default=datetime.utcnow)
    icon = db.Column(db.String(50))

class QuizProgress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'))
    current_question = db.Column(db.Integer)
    answers = db.Column(db.Text)  # JSON string of answers
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)

class QuizPrerequisite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'))
    prerequisite_quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'))
    minimum_score = db.Column(db.Float, default=0.0)

class Settings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    site_name = db.Column(db.String(100), default='Connect Shiksha Quiz App')
    default_duration = db.Column(db.Integer, default=30)
    default_passing_percentage = db.Column(db.Float, default=60.0)
    max_attempts = db.Column(db.Integer, default=1)

# Create tables
with app.app_context():
    # Drop all tables
    db.drop_all()
    # Create all tables
    db.create_all()
    # Create default admin user if not exists
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin',
            email='admin@example.com',  # Add email for admin
            password_hash=generate_password_hash('admin123'),
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()
    
    # Create default settings if not exists
    if not Settings.query.first():
        settings = Settings()
        db.session.add(settings)
        db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = request.form.get('remember') == 'on'
        
        # Try to find user by email or username
        user = User.query.filter((User.email == email) | (User.username == email)).first()
        
        if user and user.check_password(password):
            login_user(user, remember=remember)
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            if user.is_admin:
                return redirect(url_for('dashboard'))
            else:
                return redirect(url_for('student_dashboard'))
        else:
            flash('Invalid email/username or password', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
            
        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'danger')
            return redirect(url_for('register'))
            
        user = User(
            username=username,
            email=email,
            is_admin=False
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/admin/dashboard')
@login_required
@admin_required
def dashboard():
    # Get the requested tab from query parameters, default to 'dashboard'
    tab = request.args.get('tab', 'dashboard')
    
    # Get all necessary data for the dashboard
    quizzes = Quiz.query.all()
    users = User.query.all()
    attempts = Result.query.all()
    recent_attempts = Result.query.order_by(Result.completed_at.desc()).limit(5).all()
    settings = Settings.query.first()
    
    # Calculate average score
    if attempts:
        avg_score = sum(attempt.score for attempt in attempts) / len(attempts)
    else:
        avg_score = 0
    
    # Get popular quizzes
    popular_quizzes = Quiz.query.order_by(Quiz.results.any()).limit(5).all()
    
    return render_template('admin_dashboard.html',
                         quizzes=quizzes,
                         users=users,
                         attempts=attempts,
                         recent_attempts=recent_attempts,
                         avg_score=avg_score,
                         popular_quizzes=popular_quizzes,
                         settings=settings,
                         active_tab=tab)

@app.route('/admin/upload_quiz', methods=['POST'])
@login_required
def upload_quiz():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        if 'quiz_file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['quiz_file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not file.filename.endswith('.json'):
            return jsonify({'error': 'File must be a JSON file'}), 400
        
        # Read and parse the JSON file
        quiz_data = json.load(file)
        
        # Validate required fields
        required_fields = ['title', 'duration', 'questions']
        for field in required_fields:
            if field not in quiz_data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Create new quiz
        quiz = Quiz(
            title=quiz_data['title'],
            description=quiz_data.get('description', ''),
            duration=quiz_data['duration'],
            category_id=quiz_data.get('category_id', 1),
            difficulty=quiz_data.get('difficulty', 'medium'),
            passing_percentage=quiz_data.get('passing_percentage', 60.0),
            max_attempts=quiz_data.get('max_attempts', 1)
        )
        db.session.add(quiz)
        db.session.flush()  # Get the quiz ID
        
        # Add questions
        for q_data in quiz_data['questions']:
            question = Question(
                quiz_id=quiz.id,
                question_text=q_data['question_text'],
                question_type=q_data.get('question_type', 'multiple_choice'),
                points=q_data.get('points', 1),
                negative_marking=q_data.get('negative_marking', 0.0),
                explanation=q_data.get('explanation', '')
            )
            db.session.add(question)
            db.session.flush()  # Get the question ID
            
            # Add options for multiple choice questions
            if q_data.get('question_type') == 'multiple_choice' and 'options' in q_data:
                for option_data in q_data['options']:
                    option = Option(
                        question_id=question.id,
                        text=option_data['text'],
                        is_correct=option_data.get('is_correct', False)
                    )
                    db.session.add(option)
            # Add correct answer for other question types
            elif 'correct_answer' in q_data:
                option = Option(
                    question_id=question.id,
                    text=q_data['correct_answer'],
                    is_correct=True
                )
                db.session.add(option)
        
        db.session.commit()
        return jsonify({'message': 'Quiz uploaded successfully', 'quiz_id': quiz.id})
    
    except json.JSONDecodeError:
        return jsonify({'error': 'Invalid JSON file'}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/quiz/<int:quiz_id>')
@login_required
def take_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    
    # Check if user has already attempted this quiz
    existing_result = Result.query.filter_by(
        user_id=current_user.id,
        quiz_id=quiz_id
    ).first()
    
    if existing_result:
        flash('You have already attempted this quiz!', 'warning')
        return redirect(url_for('dashboard'))
    
    return render_template('quiz.html', quiz=quiz)

@app.route('/submit_quiz/<int:quiz_id>', methods=['POST'])
@login_required
def submit_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    answers = request.json
    score = 0
    total_points = 0
    
    # Debug print to see what we're receiving
    print("Received answers:", answers)
    
    # Create a new result
    result = Result(
        user_id=current_user.id,
        quiz_id=quiz_id,
        score=0,  # Will update this later
        total_questions=len(quiz.questions),
        time_taken=answers.get('time_taken', 0),
        status='completed'
    )
    db.session.add(result)
    db.session.flush()  # This assigns an ID to the result
    
    # Process each question and save user answers
    for question in quiz.questions:
        question_id = str(question.id)
        points_earned = 0
        is_correct = False
        
        if question_id in answers:
            user_answer = answers[question_id]
            
            # Create user answer record
            answer_record = UserAnswer(
                result_id=result.id,
                question_id=question.id,
                answer=user_answer
            )
            
            # Check if answer is correct based on question type
            if question.question_type == 'multiple_choice':
                correct_option = Option.query.filter_by(
                    question_id=question.id,
                    is_correct=True
                ).first()
                if correct_option and str(correct_option.id) == user_answer:
                    is_correct = True
                    points_earned = question.points
                elif question.negative_marking > 0:
                    points_earned = -question.negative_marking
                    
            elif question.question_type == 'true_false':
                if user_answer == question.correct_answer:
                    is_correct = True
                    points_earned = question.points
                elif question.negative_marking > 0:
                    points_earned = -question.negative_marking
                    
            elif question.question_type == 'short_answer':
                if user_answer.lower().strip() == question.correct_answer.lower().strip():
                    is_correct = True
                    points_earned = question.points
                    
            answer_record.is_correct = is_correct
            answer_record.points_earned = points_earned
            db.session.add(answer_record)
            
            score += points_earned
            total_points += question.points
    
    # Update the result with final score
    if total_points > 0:
        percentage = (score / total_points) * 100
    else:
        percentage = 0
        
    result.score = score
    result.status = 'passed' if percentage >= quiz.passing_percentage else 'failed'
    
    db.session.commit()
    
    return jsonify({
        'score': score,
        'total_points': total_points,
        'percentage': round(percentage, 2),
        'status': result.status
    })

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/admin/edit_quiz/<int:quiz_id>', methods=['GET', 'POST'])
@login_required
def edit_quiz(quiz_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    quiz = Quiz.query.get_or_404(quiz_id)
    
    if request.method == 'POST':
        try:
            data = request.json
            quiz.title = data.get('title', quiz.title)
            quiz.duration = data.get('duration', quiz.duration)
            if 'questions' in data:
                quiz.questions = data['questions']
            db.session.commit()
            return jsonify({'message': 'Quiz updated successfully'})
        except Exception as e:
            return jsonify({'error': str(e)}), 400
    
    return render_template('edit_quiz.html', quiz=quiz)

@app.route('/admin/delete_quiz/<int:quiz_id>', methods=['POST'])
@login_required
def delete_quiz(quiz_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    quiz = Quiz.query.get_or_404(quiz_id)
    db.session.delete(quiz)
    db.session.commit()
    return jsonify({'message': 'Quiz deleted successfully'})

@app.route('/admin/create_user', methods=['POST'])
@login_required
@admin_required
def create_user():
    data = request.get_json()
    
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'success': False, 'message': 'Username already exists'})
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'success': False, 'message': 'Email already exists'})
    
    user = User(
        username=data['username'],
        email=data['email'],
        is_admin=data['is_admin']
    )
    user.set_password(data['password'])
    
    db.session.add(user)
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/admin/delete_user/<int:user_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    
    if user == current_user:
        return jsonify({'success': False, 'message': 'Cannot delete your own account'})
    
    db.session.delete(user)
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/student/dashboard')
@login_required
def student_dashboard():
    # Get the requested tab from query parameters, default to 'dashboard'
    tab = request.args.get('tab', 'dashboard')
    
    # For students, get both available quizzes and their results
    quizzes = Quiz.query.all()
    results = Result.query.filter_by(user_id=current_user.id).all()
    # Create a set of quiz IDs that the user has already attempted
    attempted_quizzes = {result.quiz_id for result in results}
    
    return render_template('student_dashboard.html', 
                         quizzes=quizzes,
                         results=results,
                         attempted_quizzes=attempted_quizzes,
                         active_tab=tab)

@app.route('/admin/manage_quizzes')
@login_required
@admin_required
def manage_quizzes():
    quizzes = Quiz.query.all()
    categories = Category.query.all()
    return render_template('admin/manage_quizzes.html', quizzes=quizzes, categories=categories)

@app.route('/admin/manage_users')
@login_required
@admin_required
def manage_users():
    users = User.query.all()
    return render_template('admin/manage_users.html', users=users)

@app.route('/admin/reports')
@login_required
@admin_required
def reports():
    # Get statistics for reports
    total_users = User.query.count()
    total_quizzes = Quiz.query.count()
    total_attempts = Result.query.count()
    
    # Get recent quiz attempts
    recent_attempts = Result.query.order_by(Result.completed_at.desc()).limit(10).all()
    
    # Get quiz performance statistics
    quiz_stats = db.session.query(
        Quiz.title,
        db.func.count(Result.id).label('attempts'),
        db.func.avg(Result.score).label('avg_score')
    ).join(Result).group_by(Quiz.id).all()
    
    # Get category distribution
    categories = db.session.query(
        Category.name,
        db.func.count(Quiz.id).label('quiz_count')
    ).outerjoin(Quiz).group_by(Category.id, Category.name).all()
    
    return render_template('admin/reports.html',
                         total_users=total_users,
                         total_quizzes=total_quizzes,
                         total_attempts=total_attempts,
                         recent_attempts=recent_attempts,
                         quiz_stats=quiz_stats,
                         categories=categories)

@app.route('/admin/create_category', methods=['POST'])
@login_required
@admin_required
def create_category():
    data = request.get_json()
    
    if Category.query.filter_by(name=data['name']).first():
        return jsonify({'success': False, 'message': 'Category already exists'})
    
    category = Category(
        name=data['name'],
        description=data.get('description', '')
    )
    
    db.session.add(category)
    db.session.commit()
    
    return jsonify({'success': True})

if __name__ == '__main__':
    app.run(debug=True) 