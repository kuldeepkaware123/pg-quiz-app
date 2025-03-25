# Quiz Application

A modern web-based quiz application built with Flask that allows students to take timed tests and administrators to manage quizzes.

## Features

- User authentication (student and admin roles)
- Admin dashboard for quiz management
- JSON-based quiz upload system
- Timed quizzes with automatic submission
- Real-time quiz results
- Modern and responsive UI
- Student dashboard with performance history

## Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd quiz-app
```

2. Create a virtual environment and activate it:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Run the application:
```bash
python app.py
```

5. Open your browser and navigate to `http://localhost:5000`

## Quiz JSON Format

When uploading a quiz, use the following JSON format:

```json
{
    "title": "Quiz Title",
    "duration": 30,
    "questions": [
        {
            "id": 1,
            "question": "What is the capital of France?",
            "options": ["London", "Paris", "Berlin", "Madrid"],
            "correct_answer": "Paris"
        },
        {
            "id": 2,
            "question": "Which planet is known as the Red Planet?",
            "options": ["Venus", "Mars", "Jupiter", "Saturn"],
            "correct_answer": "Mars"
        }
    ]
}
```

## Creating an Admin User

To create an admin user, you can use the Python shell:

```python
from app import app, db, User
from werkzeug.security import generate_password_hash

with app.app_context():
    admin = User(
        username='admin',
        password_hash=generate_password_hash('your-password'),
        is_admin=True
    )
    db.session.add(admin)
    db.session.commit()
```

## Usage

1. Register as a student or login as admin
2. Admin can:
   - Upload new quizzes using JSON files
   - View all available quizzes
   - Monitor student results
3. Students can:
   - View available quizzes
   - Take timed quizzes
   - View their results and performance history

## Technologies Used

- Flask
- SQLite
- Bootstrap 5
- Font Awesome
- JavaScript 