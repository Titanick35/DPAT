from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
from populate_db import populate_db  # Import the populate_db function

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key')  # Use environment variable for security

# Database configuration for Render PostgreSQL
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://dpat_db_user:zdZVlEdjMOqzHv8ofBIAhPaONUxs43BY@dpg-cvped8je5dus73cfmsvg-a.virginia-postgres.render.com/dpat_db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
print(f"Database URI: {app.config['SQLALCHEMY_DATABASE_URI']}")
db = SQLAlchemy(app)

# Initialize Flask-Migrate
migrate = Migrate(app, db)  # Add this line to set up Flask-Migrate

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'sign_in'

# User model
# In app.py, update the User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)  # Increased length for hashed password
    role = db.Column(db.String(20), nullable=False, default='user')
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'))

    def get_id(self):
        return str(self.id)

# Organization model
class Organization(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    goal_date = db.Column(db.DateTime)  # Existing column for goal date
    compliance_score = db.Column(db.Float, default=0.0)  # New column for compliance score
    admin = db.relationship('User', backref='organization_admin', uselist=False, foreign_keys=[admin_id])
    users = db.relationship('User', backref='organization', foreign_keys='User.organization_id')

# Assessment score model
class AssessmentScore(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    date_taken = db.Column(db.DateTime, default=db.func.current_timestamp())
    user = db.relationship('User', backref='assessment_scores')

# To-Do Item model
class ToDoItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    completed = db.Column(db.Boolean, default=False)
    organization = db.relationship('Organization', backref='todo_items')

class ChecklistItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), unique=True, nullable=False)  # e.g., 'lawful_basis_identified'
    description = db.Column(db.String(200), nullable=False)  # e.g., 'Identify and document lawful basis for data processing'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Temporary endpoint to initialize the database
@app.route('/init-db', methods=['GET'])
def init_database():
    try:
        populate_db()  # Call the populate_db function from populate_db.py
        return "Database initialized successfully!", 200
    except Exception as e:
        return f"Error initializing database: {str(e)}", 500

# Routes
@app.route('/')
def home():
    if current_user.is_authenticated and current_user.email == 'sysadmin@dpat.org':
        flash('Access denied. System Admin can only access System Manager.')
        return redirect(url_for('sys_manager'))
    return render_template('home.html')

@app.route('/sign_in', methods=['GET', 'POST'])
def sign_in():
    if request.method == 'POST':
        email = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            if email == 'sysadmin@dpat.org':
                return redirect(url_for('sys_manager'))
            return redirect(url_for('home'))
        else:
            flash('Login credentials failed.')
    return render_template('sign_in.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.email == 'sysadmin@dpat.org':
        flash('Access denied. System Admin can only access System Manager.')
        return redirect(url_for('sys_manager'))

    # Fetch organization data
    org = Organization.query.filter_by(id=current_user.organization_id).first()
    compliance_score = org.compliance_score if org else 0.0
    goal_date = org.goal_date.strftime('%B %d') if org and org.goal_date else None
    days_remaining = None
    if org and org.goal_date:
        today = datetime.now()
        diff_time = org.goal_date - today
        days_remaining = diff_time.days

    # Pass a flag to indicate if the user is an admin
    is_admin = current_user.role == 'admin'

    return render_template('dashboard.html',
                           avg_score=f"{compliance_score:.1f}",
                           goal_date=goal_date,
                           days_remaining=days_remaining,
                           is_admin=is_admin)

@app.route('/set_goal_date', methods=['POST'])
@login_required
def set_goal_date():
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.get_json()
    goal_date_str = data.get('goal_date')
    goal_date = datetime.strptime(goal_date_str, '%B %d')
    # Set year to current year
    goal_date = goal_date.replace(year=datetime.now().year)

    org = Organization.query.filter_by(id=current_user.organization_id).first()
    if org:
        org.goal_date = goal_date
        db.session.commit()

        today = datetime.now()
        diff_time = goal_date - today
        days_remaining = diff_time.days

        return jsonify({'days_remaining': days_remaining})
    return jsonify({'error': 'Organization not found'}), 404

@app.route('/assessment', methods=['GET', 'POST'])
@login_required
def assessment():
    if current_user.email == 'sysadmin@dpat.org':
        flash('Access denied. System Admin can only access System Manager.')
        return redirect(url_for('sys_manager'))
    if request.method == 'POST':
        # Scoring logic for 20 questions
        score = 0
        total_questions = 20
        correct_answers = {
            'q1': 'b', 'q2': 'b', 'q3': 'b', 'q4': 'b', 'q5': 'd', 'q6': 'b',
            'q7': 'a', 'q8': 'c', 'q9': 'b', 'q10': 'b',
            'q11': ['a', 'c'], 'q12': ['a', 'b', 'c'], 'q13': ['a', 'b', 'd'],
            'q14': ['a', 'c', 'd'], 'q15': ['a', 'c'],
            'q16': ['a', 'b', 'c'], 'q17': ['a', 'b', 'c'],
            'q18': ['a', 'b', 'c'], 'q19': ['a', 'c'], 'q20': ['a', 'b', 'd']
        }
        for q in range(1, 11):  # Radio button questions
            answer = request.form.get(f'q{q}')
            if answer == correct_answers[f'q{q}']:
                score += 5
        for q in range(11, 21):  # Checkbox questions
            answers = request.form.getlist(f'q{q}')
            if sorted(answers) == sorted(correct_answers[f'q{q}']):
                score += 5

        new_score = AssessmentScore(user_id=current_user.id, score=score, date_taken=datetime.now())
        db.session.add(new_score)
        db.session.commit()
        flash('Assessment submitted successfully!', 'success')
        return redirect(url_for('results_user', score=score))
    return render_template('assessment.html')

@app.route('/results_user')
@login_required
def results_user():
    if current_user.email == 'sysadmin@dpat.org':
        flash('Access denied. System Admin can only access System Manager.')
        return redirect(url_for('sys_manager'))
    score = request.args.get('score', default=0, type=int)
    return render_template('results_user.html', score=score)

@app.route('/results_admin')
@login_required
def results_admin():
    if current_user.email == 'sysadmin@dpat.org':
        flash('Access denied. System Admin can only access System Manager.')
        return redirect(url_for('sys_manager'))
    elif current_user.role != 'admin':
        flash('Access denied. Only admins can view admin results.')
        return redirect(url_for('dashboard'))

    users_data = User.query.filter_by(organization_id=current_user.organization_id).all()
    scores = AssessmentScore.query.join(User).filter(User.organization_id == current_user.organization_id).all()
    avg_score = sum(score.score for score in scores) / len(scores) if scores else 0
    return render_template('results_admin.html', avg_score=f"{avg_score:.1f}%", users=users_data)

@app.route('/library')
@login_required
def library():
    if current_user.email == 'sysadmin@dpat.org':
        flash('Access denied. System Admin can only access System Manager.')
        return redirect(url_for('sys_manager'))
    return render_template('library.html')

@app.route('/breach_info')
@login_required
def breach_info():
    if current_user.email == 'sysadmin@dpat.org':
        flash('Access denied. System Admin can only access System Manager.')
        return redirect(url_for('sys_manager'))
    return render_template('breach_info.html')

@app.route('/risks_bp')
@login_required
def risks_bp():
    if current_user.email == 'sysadmin@dpat.org':
        flash('Access denied. System Admin can only access System Manager.')
        return redirect(url_for('sys_manager'))
    return render_template('risks_bp.html')

@app.route('/org_manager', methods=['GET', 'POST'])
@login_required
def org_manager():
    if current_user.email == 'sysadmin@dpat.org':
        flash('Access denied. System Admin can only access System Manager.')
        return redirect(url_for('sys_manager'))
    elif current_user.role != 'admin':
        flash('Access denied. Only admins can manage organizations.')
        return redirect(url_for('dashboard'))

    # Fetch the current admin's organization
    organization = Organization.query.filter_by(id=current_user.organization_id).first()
    if not organization:
        flash('No organization found for this admin. Please contact the system administrator.')
        return redirect(url_for('dashboard'))

    # Set the organization name for display
    organization_name = organization.name

    # Fetch users for the current admin's organization only
    users_data = User.query.filter_by(organization_id=current_user.organization_id).all()

    # Handle POST request for creating a new user
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        password = request.form.get('password')
        privileges = request.form.get('privileges')

        if not email or not password or not privileges:
            flash('User creation failed. All fields (email, password, privileges) are required.')
        elif User.query.filter_by(email=email).first():
            flash('User creation failed. Email already exists.')
        else:
            try:
                new_user = User(
                    email=email,
                    password=generate_password_hash(password, method='scrypt'),  # Explicitly specify scrypt
                    role=privileges,
                    first_name=first_name,
                    last_name=last_name,
                    organization_id=current_user.organization_id
                )
                db.session.add(new_user)
                db.session.commit()
                flash(f'User {email} created successfully!', 'success')
                users_data = User.query.filter_by(organization_id=current_user.organization_id).all()
            except Exception as e:
                db.session.rollback()
                flash(f'Error creating user: {str(e)}', 'error')

    # Handle user removal via GET request with 'remove' parameter
    remove_indices = request.args.get('remove')
    if remove_indices:
        try:
            remove_ids = [int(idx) for idx in remove_indices.split(',')]
            # Ensure users to remove belong to the current admin's organization
            users_to_remove = User.query.filter(
                User.id.in_(remove_ids),
                User.email != current_user.email,  # Prevent self-deletion
                User.organization_id == current_user.organization_id
            ).all()
            if not users_to_remove:
                flash('No valid users selected for removal.', 'warning')
            else:
                for user in users_to_remove:
                    db.session.delete(user)
                db.session.commit()
                flash(f'Removed {len(users_to_remove)} user(s).', 'success')
                # Refresh users_data after removal
                users_data = User.query.filter_by(organization_id=current_user.organization_id).all()
        except ValueError:
            flash('Invalid user IDs provided for removal.', 'error')
        except Exception as e:
            db.session.rollback()
            flash(f'Error removing users: {str(e)}', 'error')

    # Render the org_manager template with the filtered users and organization name
    return render_template(
        'org_manager.html',
        users=users_data,
        organization_name=organization_name
    )

@app.route('/update_role', methods=['POST'])
@login_required
def update_role():
    if current_user.email == 'sysadmin@dpat.org':
        flash('Access denied. System Admin can only access System Manager.')
        return redirect(url_for('sys_manager'))
    elif current_user.role != 'admin':
        flash('Access denied. Only admins can update roles.')
        return redirect(url_for('org_manager'))

    email = request.form.get('email')
    new_role = request.form.get('role')
    user = User.query.filter_by(email=email).first()
    if user:
        user.role = new_role
        db.session.commit()
        flash(f"Updated role for {email} to {new_role}.")
    else:
        flash("User not found.")
    return redirect(url_for('org_manager'))

@app.route('/sys_manager', methods=['GET', 'POST'])
@login_required
def sys_manager():
    if current_user.email != 'sysadmin@dpat.org':
        flash('Access denied. Only the System Admin can access this page.')
        return redirect(url_for('dashboard' if current_user.role != 'admin' else 'org_manager'))

    if request.method == 'POST':
        org_name = request.form.get('org_name')
        admin_name = request.form.get('admin_name')
        admin_username = request.form.get('admin_username')
        admin_password = request.form.get('admin_password')

        if org_name and admin_name and admin_username and admin_password:
            if not User.query.filter_by(email=admin_username).first():
                new_admin = User(
                    email=admin_username,
                    password=generate_password_hash(admin_password, method='scrypt'),  # Explicitly specify scrypt
                    role='admin',
                    first_name=admin_name.split()[0],
                    last_name=admin_name.split()[-1] if len(admin_name.split()) > 1 else ''
                )
                db.session.add(new_admin)
                db.session.flush()

                new_org = Organization(name=org_name, admin_id=new_admin.id)
                db.session.add(new_org)
                db.session.flush()

                new_admin.organization_id = new_org.id
                db.session.commit()
                flash(f'Organization {org_name} created successfully!')
            else:
                flash('Admin username already exists.')
        else:
            flash('Organization creation failed. All fields are required.')

    remove_ids = request.args.get('remove')
    if remove_ids:
        remove_ids = [int(id) for id in remove_ids.split(',')]
        orgs_to_remove = Organization.query.filter(Organization.id.in_(remove_ids)).all()
        for org in orgs_to_remove:
            admin = User.query.get(org.admin_id)
            if admin:
                db.session.delete(admin)
            db.session.delete(org)
        db.session.commit()
        flash(f'Removed {len(orgs_to_remove)} organization(s).')

    organizations = Organization.query.all()
    return render_template('sys_manager.html', organizations=organizations)

@app.route('/checklist', methods=['GET', 'POST'])
@login_required
def checklist():
    if current_user.email == 'sysadmin@dpat.org':
        flash('Access denied. System Admin can only access System Manager.')
        return redirect(url_for('sys_manager'))
    if request.method == 'POST':
        checklist_items = request.form.getlist('checklist_items')
        all_items = {
            'lawful_basis_identified': 'Identify and document lawful basis for data processing',
            'lawful_basis_demonstrated': 'Demonstrate lawful basis for all processing activities',
            'data_minimization_necessary': 'Collect only necessary personal data',
            'data_minimization_review': 'Regularly review data to avoid excess retention',
            'data_accuracy_process': 'Ensure data accuracy with processes',
            'data_accuracy_correction': 'Allow data subjects to correct inaccurate data',
            'transparency_notices': 'Provide clear privacy notices',
            'transparency_details': 'Include details in privacy notices',
            'consent_freely_given': 'Ensure consent is freely given and unambiguous',
            'consent_management': 'Implement consent management processes',
            'consent_withdrawal': 'Provide easy consent withdrawal',
            'subject_rights_procedures': 'Have procedures for data subject rights',
            'subject_rights_response': 'Respond to requests within one month',
            'subject_rights_verification': 'Verify identity for rights requests',
            'retention_policy': 'Document data retention policy',
            'retention_disposal': 'Securely dispose of unneeded data',
            'security_measures': 'Implement data security measures',
            'security_training': 'Train employees on security practices',
            'breach_response_plan': 'Have a data breach response plan',
            'breach_notification': 'Notify authorities of breaches within 72 hours',
            'breach_subject_notification': 'Notify data subjects of breaches',
            'third_party_contracts': 'Have GDPR-compliant contracts with third parties',
            'third_party_audits': 'Audit third-party processors',
            'dpia_high_risk': 'Conduct DPIAs for high-risk activities',
            'dpia_documented': 'Document DPIAs with necessity assessment',
            'dpo_designated': 'Designate a Data Protection Officer',
            'processing_records': 'Maintain data processing records',
            'internal_audits': 'Conduct regular internal audits',
            'data_transfer_safeguards': 'Use safeguards for data transfers outside EEA',
            'data_transfer_assessment': 'Assess recipient country privacy standards',
            'employee_training': 'Train employees on GDPR principles',
            'ongoing_training': 'Provide ongoing GDPR training',
            'monitoring_processes': 'Monitor GDPR compliance internally',
            'gdpr_review': 'Review GDPR practices regularly'
        }

        # Calculate compliance score
        total_items = len(all_items)
        completed_items = len(checklist_items)
        compliance_score = (completed_items / total_items) * 100 if total_items > 0 else 0.0

        # Update the organization's compliance score
        org = Organization.query.filter_by(id=current_user.organization_id).first()
        if org:
            org.compliance_score = compliance_score
            db.session.commit()

        # Delete existing todo items for this organization
        ToDoItem.query.filter_by(organization_id=current_user.organization_id).delete()

        # Add new todo items
        for item_key, description in all_items.items():
            if item_key not in checklist_items:
                todo_item = ToDoItem(
                    organization_id=current_user.organization_id,
                    description=description
                )
                db.session.add(todo_item)

        db.session.commit()
        flash('Checklist saved successfully!', 'success')
        return redirect(url_for('to_do_list'))
    return render_template('checklist.html')

@app.route('/to_do_list')
@login_required
def to_do_list():
    if current_user.email == 'sysadmin@dpat.org':
        flash('Access denied. System Admin can only access System Manager.')
        return redirect(url_for('sys_manager'))
    todo_items = ToDoItem.query.filter_by(organization_id=current_user.organization_id).all()
    response = make_response(render_template('to_do_list.html', to_do_items=todo_items))
    session.pop('_flashes', None)
    return response

@app.route('/remove_todo/<int:todo_id>', methods=['POST'])
@login_required
def remove_todo(todo_id):
    if current_user.email == 'sysadmin@dpat.org':
        flash('Access denied. System Admin can only access System Manager.')
        return redirect(url_for('sys_manager'))

    # Fetch the to-do item
    todo = ToDoItem.query.get_or_404(todo_id)
    if todo.organization_id != current_user.organization_id:
        flash('Unauthorized access to todo item.')
        return redirect(url_for('to_do_list'))

    # Remove the to-do item
    db.session.delete(todo)
    db.session.commit()

    # Recalculate compliance score
    all_items = {
        'lawful_basis_identified': 'Identify and document lawful basis for data processing',
        'lawful_basis_demonstrated': 'Demonstrate lawful basis for all processing activities',
        'data_minimization_necessary': 'Collect only necessary personal data',
        'data_minimization_review': 'Regularly review data to avoid excess retention',
        'data_accuracy_process': 'Ensure data accuracy with processes',
        'data_accuracy_correction': 'Allow data subjects to correct inaccurate data',
        'transparency_notices': 'Provide clear privacy notices',
        'transparency_details': 'Include details in privacy notices',
        'consent_freely_given': 'Ensure consent is freely given and unambiguous',
        'consent_management': 'Implement consent management processes',
        'consent_withdrawal': 'Provide easy consent withdrawal',
        'subject_rights_procedures': 'Have procedures for data subject rights',
        'subject_rights_response': 'Respond to requests within one month',
        'subject_rights_verification': 'Verify identity for rights requests',
        'retention_policy': 'Document data retention policy',
        'retention_disposal': 'Securely dispose of unneeded data',
        'security_measures': 'Implement data security measures',
        'security_training': 'Train employees on security practices',
        'breach_response_plan': 'Have a data breach response plan',
        'breach_notification': 'Notify authorities of breaches within 72 hours',
        'breach_subject_notification': 'Notify data subjects of breaches',
        'third_party_contracts': 'Have GDPR-compliant contracts with third parties',
        'third_party_audits': 'Audit third-party processors',
        'dpia_high_risk': 'Conduct DPIAs for high-risk activities',
        'dpia_documented': 'Document DPIAs with necessity assessment',
        'dpo_designated': 'Designate a Data Protection Officer',
        'processing_records': 'Maintain data processing records',
        'internal_audits': 'Conduct regular internal audits',
        'data_transfer_safeguards': 'Use safeguards for data transfers outside EEA',
        'data_transfer_assessment': 'Assess recipient country privacy standards',
        'employee_training': 'Train employees on GDPR principles',
        'ongoing_training': 'Provide ongoing GDPR training',
        'monitoring_processes': 'Monitor GDPR compliance internally',
        'gdpr_review': 'Review GDPR practices regularly'
    }

    # Count remaining to-do items
    remaining_items = ToDoItem.query.filter_by(organization_id=current_user.organization_id).count()
    total_items = len(all_items)
    completed_items = total_items - remaining_items
    compliance_score = (completed_items / total_items) * 100 if total_items > 0 else 0.0

    # Update the organization's compliance score
    org = Organization.query.filter_by(id=current_user.organization_id).first()
    if org:
        org.compliance_score = compliance_score
        db.session.commit()

    flash('Task removed successfully!', 'success')
    return redirect(url_for('to_do_list'))

@app.route('/complete_todo/<int:todo_id>', methods=['POST'])
@login_required
def complete_todo(todo_id):
    if current_user.email == 'sysadmin@dpat.org':
        flash('Access denied. System Admin can only access System Manager.')
        return redirect(url_for('sys_manager'))

    todo = ToDoItem.query.get_or_404(todo_id)
    if todo.organization_id != current_user.organization_id:
        flash('Unauthorized access to todo item.')
        return redirect(url_for('to_do_list'))
    todo.completed = True
    db.session.commit()
    flash('Task marked as completed!')
    return redirect(url_for('to_do_list'))

@app.route('/forgot_password')
def forgot_password():
    flash('Forgot password functionality is not yet implemented.')
    return redirect(url_for('sign_in'))

@app.route('/consequences_bp')
@login_required
def consequences_bp():
    if current_user.email == 'sysadmin@dpat.org':
        flash('Access denied. System Admin can only access System Manager.')
        return redirect(url_for('sys_manager'))
    return render_template('consequences_bp.html')

if __name__ == '__main__':
    app.run(debug=True)