import pymysql
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from urllib.parse import unquote
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.engine.url import URL
from sqlalchemy import Enum
from datetime import datetime
from flask_migrate import Migrate

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Configure the MySQL database
app.config['SQLALCHEMY_DATABASE_URI'] = URL.create(
    drivername="mysql",
    username="root",
    password="Micromax@q5",  # No need to manually encode
    host="localhost",
    database="testing"
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


# Users Table
class User(db.Model):
    __tablename__ = 'Users'
    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    role = db.Column(db.String(50), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    certificates = db.Column(db.Text)

    projects = db.relationship('UsersProjects', back_populates='user')


class EAL(db.Model):
    __tablename__ = 'EALs'
    EAL = db.Column(db.String(50), primary_key=True)

    # Relationship to components specific to this EAL
    evaluation_components = db.relationship('EvaluationComponent', back_populates='eal')

    projects = db.relationship('Project', back_populates='eal')


class Project(db.Model):
    __tablename__ = 'Projects'
    project_id = db.Column(db.String(50), primary_key=True)
    project_name = db.Column(db.String(100), nullable=False)
    project_description = db.Column(db.Text)
    project_status = db.Column(db.String(50), nullable=False)
    EAL = db.Column(db.String(50), db.ForeignKey('EALs.EAL'), nullable=False)  # Many-to-One

    eal = db.relationship('EAL', back_populates='projects')
    users = db.relationship('UsersProjects', back_populates='project')
    project_evaluations = db.relationship('ProjectEvaluation', back_populates='project')  # New Relationship
    evaluator_action_statuses = db.relationship('EvaluatorActionStatus', back_populates='project')
    work_unit_statuses = db.relationship('WorkUnitStatus', back_populates='project')


# Users_Projects Table (Many-to-Many Relationship)
class UsersProjects(db.Model):
    __tablename__ = 'Users_Projects'
    user_id = db.Column(db.Integer, db.ForeignKey('Users.user_id'), primary_key=True)
    project_id = db.Column(db.String(50), db.ForeignKey('Projects.project_id'), primary_key=True)

    user = db.relationship('User', back_populates='projects')
    project = db.relationship('Project', back_populates='users')


class EvaluationComponent(db.Model):
    __tablename__ = 'EvaluationComponents'
    evaluation_component_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False, unique=False)
    class_ = db.Column("class", db.String(100), nullable=False)
    family = db.Column(db.String(100), nullable=False)
    component = db.Column(db.String(100), nullable=True)
    description = db.Column(db.Text, nullable=True)

    # New column to link EvaluationComponent to EAL
    EAL = db.Column(db.String(50), db.ForeignKey('EALs.EAL'), nullable=False)

    # Relationship to EAL
    eal = db.relationship('EAL', back_populates='evaluation_components')

    # Relationship to EvaluatorActions
    evaluator_actions = db.relationship('EvaluatorAction', back_populates='evaluation_component')
    project_evaluations = db.relationship('ProjectEvaluation', back_populates='evaluation_component')


class ProjectEvaluation(db.Model):
    __tablename__ = 'ProjectEvaluations'
    project_evaluation_id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    project_id = db.Column(db.String(50), db.ForeignKey('Projects.project_id'), nullable=False)
    evaluation_component_id = db.Column(db.Integer, db.ForeignKey('EvaluationComponents.evaluation_component_id'),
                                        nullable=False)

    status = db.Column(
        db.String(50),
        nullable=False,
        default="Inconclusive"
    )

    __table_args__ = (
        db.CheckConstraint(status.in_(["Pass", "Fail", "Inconclusive"]), name="status_check"),
    )

    # Relationships
    project = db.relationship('Project', back_populates='project_evaluations')
    evaluation_component = db.relationship('EvaluationComponent', back_populates='project_evaluations')


class EvaluatorAction(db.Model):
    __tablename__ = 'EvaluatorActions'
    action_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    action_name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    evaluation_component_id = db.Column(db.Integer, db.ForeignKey('EvaluationComponents.evaluation_component_id'))

    # Relationships
    evaluation_component = db.relationship('EvaluationComponent', back_populates='evaluator_actions')
    evaluator_action_statuses = db.relationship('EvaluatorActionStatus', back_populates='evaluator_action')


class EvaluatorActionStatus(db.Model):
    __tablename__ = 'EvaluatorActionStatuses'
    status_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    evaluator_action_id = db.Column(db.Integer, db.ForeignKey('EvaluatorActions.action_id'), nullable=False)
    project_id = db.Column(db.String(50), db.ForeignKey('Projects.project_id'), nullable=False)
    status = db.Column(db.String(50), nullable=False, default='Inconclusive')

    # Relationships
    evaluator_action = db.relationship('EvaluatorAction', back_populates='evaluator_action_statuses')
    project = db.relationship('Project', back_populates='evaluator_action_statuses')


class WorkUnit(db.Model):
    __tablename__ = 'WorkUnits'
    work_unit_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    work_unit_name = db.Column(db.String(100), nullable=False)
    evaluator_action_id = db.Column(db.Integer, db.ForeignKey('EvaluatorActions.action_id'), nullable=False)
    description = db.Column(db.Text, nullable=True)

    # Relationships
    evaluator_action = db.relationship('EvaluatorAction', back_populates='work_units')
    work_unit_statuses = db.relationship('WorkUnitStatus', back_populates='work_unit')
    subjects = db.relationship('Subject', back_populates='work_unit')


class WorkUnitStatus(db.Model):
    __tablename__ = 'WorkUnitStatuses'
    status_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    work_unit_id = db.Column(db.Integer, db.ForeignKey('WorkUnits.work_unit_id'), nullable=False)
    project_id = db.Column(db.String(50), db.ForeignKey('Projects.project_id'), nullable=False)
    status = db.Column(db.String(50), nullable=False, default='Inconclusive')

    # New columns
    last_updated_by = db.Column(db.Integer, db.ForeignKey('Users.user_id'), nullable=True)
    last_modified = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Enforcing the status constraint
    __table_args__ = (
        db.CheckConstraint(status.in_(["Pass", "Fail", "Inconclusive"]), name="status_check_new"),
    )

    # Relationships
    work_unit = db.relationship('WorkUnit', back_populates='work_unit_statuses')
    project = db.relationship('Project', back_populates='work_unit_statuses')
    user = db.relationship('User', back_populates='work_unit_statuses')


class Subject(db.Model):
    __tablename__ = 'Subjects'
    subject_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    subject_name = db.Column(db.String(100), nullable=False)
    work_unit_id = db.Column(db.Integer, db.ForeignKey('WorkUnits.work_unit_id'), nullable=False)

    # Relationships
    work_unit = db.relationship('WorkUnit', back_populates='subjects')
    subject_values = db.relationship('SubjectValue', back_populates='subject')


class SubjectValue(db.Model):
    __tablename__ = 'SubjectValues'
    value_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    subject_id = db.Column(db.Integer, db.ForeignKey('Subjects.subject_id'), nullable=False)
    project_id = db.Column(db.String(50), db.ForeignKey('Projects.project_id'), nullable=False)
    value = db.Column(db.Text, nullable=False)

    # Relationships
    subject = db.relationship('Subject', back_populates='subject_values')
    project = db.relationship('Project', back_populates='subject_values')


# Authentication decorator
def authenticate(func):
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash("You need to log in first.", "error")
            return redirect(url_for('login'))
        return func(*args, **kwargs)

    wrapper.__name__ = func.__name__  # Preserve the function name for Flask routing
    return wrapper


# Mock login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Simulating a successful login (user_id = 1 for demo purposes)
        session['user_id'] = 1
        session['username'] = 'John Doe'
        flash("Login successful!", "success")
        return redirect(url_for('dashboard'))
    return render_template('login.html')


# Dashboard route (protected)
@app.route('/dashboard')
@authenticate
def dashboard():
    return render_template('dashboard.html', user={'name': session['username'], 'image': 'default.png'})


# Projects under evaluation route (protected)
@app.route('/projects/under_evaluation')
@authenticate
def projects_under_evaluation():
    user_id = session['user_id']
    try:
        # Connect to the database
        conn = pymysql.connect(**db_config)
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        print("ok.....................................")
        # Query for projects under evaluation for the logged-in user
        query = """
            SELECT project_id, project_name, EAL
            FROM projects
            WHERE status = 'Under Evaluation' AND user_id = %s
        """
        cursor.execute(query, (user_id,))
        user_projects = cursor.fetchall()

        # Close connection
        cursor.close()
        conn.close()
    except pymysql.MySQLError as err:
        flash(f"Database error: {err}", "error")
        user_projects = []

    return render_template('projects_under_evaluation.html', projects=user_projects)


# Logout route
@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))


@app.route('/update_image', methods=['POST'])
def update_image():
    if 'user' not in session:
        return redirect(url_for('login'))
    new_image = request.form.get('image')
    # In real scenarios, save the uploaded image and update user data
    session['user']['image'] = new_image or session['user']['image']
    return redirect(url_for('dashboard'))


@app.route('/projects/evaluation/<project_id>')
@authenticate
def evaluation_page(project_id):
    try:
        # Store the project_id in the session
        session['project_id'] = project_id

        # Database connection
        conn = pymysql.connect(**db_config)
        cursor = conn.cursor(pymysql.cursors.DictCursor)

        # Query for project details
        query = "SELECT project_name, EAL FROM projects WHERE project_id = %s"
        cursor.execute(query, (project_id,))
        project = cursor.fetchone()

        # Close the database connection
        cursor.close()
        conn.close()

        # Check if project exists
        if not project:
            flash("Project not found.", "error")
            return redirect(url_for('projects_under_evaluation'))

        # Extract the numeric part of EAL and convert to integer
        eal_text = project['EAL']  # Example: "EAL 1"
        eal = int(eal_text.split()[1])  # Split by space and get the numeric part

        # Render the evaluation page
        return render_template(
            'evaluation_page.html',
            project_id=project_id,
            project_name=project['project_name'],
            eal=eal
        )
    except pymysql.MySQLError as err:
        flash(f"Database error: {err}", "error")
        return redirect(url_for('projects_under_evaluation'))


@app.route('/evaluation_details/<project_id>/<int:eal>')
@authenticate
def evaluation_details(project_id, eal):
    try:
        # Query the database for the project details and evaluation details
        conn = pymysql.connect(**db_config)
        cursor = conn.cursor(pymysql.cursors.DictCursor)

        # Query for project details
        project_query = "SELECT project_name FROM projects WHERE project_id = %s"
        cursor.execute(project_query, (project_id,))
        project = cursor.fetchone()

        if not project:
            flash("Project not found.", "error")
            return redirect(url_for('projects_under_evaluation'))

        # Here, you can add additional logic for evaluation details if needed

        project_name = project['project_name']
        cursor.close()
        conn.close()
    except pymysql.MySQLError as err:
        flash(f"Database error: {err}", "error")
        return redirect(url_for('projects_under_evaluation'))

    return render_template(
        'evaluation_details.html',
        project_id=project_id,
        project_name=project_name,
        eal=eal
    )


@app.route('/evaluation_component', methods=['POST'])
@authenticate
def evaluation_component():
    # Ensure 'project_id' exists in session
    class_value = request.form.get('CLASS')
    family = request.form.get('family')
    component = request.form.get('component')
    project_id = request.form.get('project_id')

    # Process the values (you can add logic here depending on the values received)
    # For example:
    if class_value and family and component and project_id:
        # Example logic based on the parameters
        # In this case, just printing them out or you can query your database or perform other actions
        print(
            f"Received POST request with CLASS: {class_value}, Family: {family}, Component: {component}, Project id: {project_id}")

    try:
        # Fetch details for the specific component
        conn = pymysql.connect(**db_config)
        cursor = conn.cursor(pymysql.cursors.DictCursor)

        # Example: Query to fetch family and component details
        query = """
            SELECT description
            FROM evaluation_component
            WHERE family = %s AND component = %s
        """
        cursor.execute(query, (family, component))
        component_details = cursor.fetchone()

        EVALUATION_COMPONENT = component
        query = """
            SELECT OBJECTIVES, INPUT, APPLICATION_NOTES, ACTN, ACTN2
            FROM EVALUATION_SUB_ACTIVITY
            WHERE EVALUATION_COMPONENT = %s
        """
        cursor.execute(query, (EVALUATION_COMPONENT))
        component_sub_activity = cursor.fetchone()

        actn1 = unquote(component_sub_activity['ACTN']).strip()
        actn2 = unquote(component_sub_activity['ACTN2']).strip()

        # Example: Query to fetch family and component details
        query = """
            SELECT status
            FROM WORK_UNITS
            WHERE actn = %s 
        """
        cursor.execute(query, (actn1,))
        status_details_actn1 = cursor.fetchall()

        # Example: Query to fetch family and component details
        query = """
            SELECT status
            FROM WORK_UNITS
            WHERE actn = %s 
        """
        cursor.execute(query, (actn2,))
        status_details_actn2 = cursor.fetchall()

        # Extract status values
        status_values = [row['status'] for row in status_details_actn1]

        # Logic to determine the overall status
        if 'Fail' in status_values:
            overall_status_actn1 = 'Fail'
        elif 'Inconclusive' in status_values:
            overall_status_actn1 = 'Inconclusive'
        elif all(status == 'Pass' for status in status_values):
            overall_status_actn1 = 'Pass'
        else:
            overall_status_actn1 = 'Unknown'  # Just in case there's a status not accounted for

        # Extract status values
        status_values = [row['status'] for row in status_details_actn2]

        # Logic to determine the overall status
        if 'Fail' in status_values:
            overall_status_actn2 = 'Fail'
        elif 'Inconclusive' in status_values:
            overall_status_actn2 = 'Inconclusive'
        elif all(status == 'Pass' for status in status_values):
            overall_status_actn2 = 'Pass'
        else:
            overall_status_actn2 = 'Unknown'  # Just in case there's a status not accounted for

        cursor.close()
        conn.close()
        # Check if details exist
        if not component_details:
            flash(f"No details found for {component} in {family}.", "error")
            return redirect(url_for('evaluation_page', project_id=project_id))

        # Render the component page
        return render_template(
            'evaluation_component.html',
            CLASS=class_value,
            family=family,
            component=component,
            description=component_details['description'],
            project_id=project_id,
            objectives=component_sub_activity['OBJECTIVES'],
            input=component_sub_activity['INPUT'],
            application_notes=component_sub_activity['APPLICATION_NOTES'],
            action1=component_sub_activity['ACTN'],
            action2=component_sub_activity['ACTN2'],
            overall_status_actn1=overall_status_actn1,
            overall_status_actn2=overall_status_actn2
        )
    except pymysql.MySQLError as err:
        flash(f"Database error: {err}", "error")
        return redirect(url_for('evaluation_page', project_id=project_id))


@app.route('/fetch_work_units', methods=['POST'])
@authenticate
def fetch_work_units():
    print("Starting fetch_work_units...")
    actn = request.form.get('actn')
    project_id = request.form.get('project_id')
    actn = unquote(actn).strip()
    try:
        # Establish the database connection
        conn = pymysql.connect(**db_config)
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        # Query for project details
        query = "SELECT project_name FROM projects WHERE project_id = %s"
        cursor.execute(query, (project_id,))
        project = cursor.fetchone()
        print(f"Fetching work units for actn: {actn}")
        # Fetch work units for the given component
        query = """
            SELECT work_unit_id, work_unit_name, status, last_updated_by, last_modified_on
            FROM WORK_UNITS
            WHERE actn = %s
        """
        print(f"Executing query: {query} with parameters: {actn}")
        try:
            cursor.execute(query, (actn,))
            work_units = cursor.fetchall()
            print(f"Fetched work units: {work_units}")
        except Exception as e:
            print(f"Error executing query: {e}")

        # Close cursor and connection
        cursor.close()
        conn.close()

        # Check if no work units were found
        if not work_units:
            flash(f"No work units found for action: {actn}", "warning")

        # Render the work units page
        return render_template(
            'work_units.html',
            work_units=work_units,
            actn=actn,
            project_id=project_id,
            project_name=project['project_name']
        )
    except Exception as e:
        # Log and flash error message if something goes wrong
        flash(f"An error occurred: {str(e)}", "error")
        return redirect(url_for('projects_under_evaluation'))


@app.route('/download_document/<string:project_id>/<string:component>/<string:document_type>', methods=['GET'])
def download_document(project_id, component, document_type):
    try:
        # Connect to the database
        conn = pymysql.connect(**db_config)
        cursor = conn.cursor(pymysql.cursors.DictCursor)

        # Query to fetch the document URL based on project_id, component, and document_type
        query = """
            SELECT document_name, document_url
            FROM INPUT_DOCUMENTS
            WHERE project_id = %s AND component = %s AND document_type = %s
        """
        cursor.execute(query, (project_id, component, document_type))
        document = cursor.fetchone()

        # Close the connection
        cursor.close()
        conn.close()

        if not document:
            flash("Document not found!", "error")
            return redirect(url_for('work_units_page', component=component))

        # Return the file for download
        return send_file(document['document_url'], as_attachment=True, download_name=document['document_name'])
    except Exception as e:
        flash(f"An error occurred: {str(e)}", "error")
        return redirect(url_for('work_units_page', component=component))


@app.route('/development_overview', methods=['GET'])
def development_overview():
    try:
        # Database connection
        conn = pymysql.connect(**db_config)
        cursor = conn.cursor(pymysql.cursors.DictCursor)

        # Query to fetch development overview content (example placeholder query)
        query = """
            SELECT component, description, evidence_url
            FROM DEVELOPMENT_OVERVIEW
        """
        cursor.execute(query)
        development_data = cursor.fetchall()

        cursor.close()
        conn.close()

        # Render the development overview template
        return render_template(
            'development_overview.html',
            development_data=development_data
        )
    except Exception as e:
        print(f"Error: {e}")
        return "An error occurred while fetching development overview.", 500


@app.route('/view_work_unit', methods=['POST'])
def view_work_unit():
    work_unit_id = request.form.get('work_unit_id')
    project_id = request.form.get('project_id')

    try:
        # Database connection
        conn = pymysql.connect(**db_config)
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        # Query for project details
        query = "SELECT project_name FROM projects WHERE project_id = %s"
        cursor.execute(query, (project_id,))
        project = cursor.fetchone()
        # Fetch work unit details
        query = """
            SELECT work_unit_name, description
            FROM WORK_UNITS
            WHERE work_unit_id = %s
        """
        cursor.execute(query, (work_unit_id,))
        work_unit = cursor.fetchone()

        work_unit_name = work_unit['work_unit_name']
        print(work_unit_name)
        query = """
            SELECT subject, work_unit_subject_id
            FROM work_unit_subject
            WHERE work_unit_name = %s
        """
        cursor.execute(query, (work_unit_name,))
        work_unit_subjects = cursor.fetchall()
        print(work_unit_subjects)

        cursor.close()
        conn.close()

        # Render the work unit details page
        return render_template(
            'work_unit_details.html',
            work_unit=work_unit,
            work_unit_id=work_unit_id,
            project_id=project_id,
            project_name=project['project_name'],
            work_unit_subjects=work_unit_subjects

        )
    except Exception as e:
        flash(f"Error fetching work unit details: {e}", "error")
        # return redirect(url_for('fetch_work_units', component=session.get('component')))


@app.route('/save-comments', methods=['POST'])
def save_comments():
    work_unit_id = request.form.get('work_unit_id')
    project_id = request.form.get('project_id')
    try:
        # Extract JSON data from the request

        data = request.get_json()  # Get the JSON payload
        if not data:
            return jsonify({"error": "Invalid JSON format"}), 400

        comments = data.get('comments')  # Expecting a dictionary of comments
        print(comments)
        evaluation_status = data.get('evaluation_status')
        print(evaluation_status)  # The evaluation status

        # Save data to the database
        save_to_database(comments, evaluation_status, work_unit_id)

        return jsonify({"message": "Data saved successfully!"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def save_to_database(comments, evaluation_status, work_unit_id):
    # Connect to MySQL

    connection = pymysql.connect(**db_config)

    cursor = connection.cursor(pymysql.cursors.DictCursor)

    # Execute the query
    query = "UPDATE work_units SET status = %s WHERE work_unit_id = %s"
    cursor.execute(query, (evaluation_status, work_unit_id))

    # Create table if it doesn't exist
    create_table_query = '''
    CREATE TABLE IF NOT EXISTS evaluation_data (
        id INT AUTO_INCREMENT PRIMARY KEY,
        subject VARCHAR(255),
        comment TEXT,
        evaluation_status VARCHAR(50)
    )
    '''
    cursor.execute(create_table_query)

    # Insert data into the table
    insert_query = '''
    INSERT INTO evaluation_data (subject, comment, evaluation_status)
    VALUES (%s, %s, %s)
    '''
    for subject, comment in comments.items():
        cursor.execute(insert_query, (subject, comment, evaluation_status))

    # Commit and close the connection
    connection.commit()
    cursor.close()
    connection.close()


if __name__ == '__main__':
    with app.app_context():  # Create database tables before running the app

        db.create_all()  # Recreates tables
        print("Database tables created successfully!")

    app.run(debug=True)  # Start the Flask app
