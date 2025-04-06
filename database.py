import sqlite3


# Initialize the database connection
def init_db():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    # Create Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT CHECK(role IN ('user', 'admin', 'sysadmin')) NOT NULL
        )
    ''')

    # Create Organizations table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS organizations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            admin_username TEXT UNIQUE NOT NULL,
            admin_password TEXT NOT NULL
        )
    ''')

    # Create Assessment Scores table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS assessment_scores (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            score INTEGER NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')

    conn.commit()
    conn.close()


# Function to add a user
def add_user(name, username, password, role):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (name, username, password, role) VALUES (?, ?, ?, ?)",
                       (name, username, password, role))
        conn.commit()
    except sqlite3.IntegrityError:
        print("Error: Username already exists!")
    conn.close()


# Function to add an organization
def add_organization(name, admin_username, admin_password):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO organizations (name, admin_username, admin_password) VALUES (?, ?, ?)",
                       (name, admin_username, admin_password))
        conn.commit()
    except sqlite3.IntegrityError:
        print("Error: Organization name or admin username already exists!")
    conn.close()


# Function to store assessment scores
def add_assessment_score(user_id, score):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO assessment_scores (user_id, score) VALUES (?, ?)", (user_id, score))
    conn.commit()
    conn.close()


# Function to get user scores
def get_user_scores():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT users.name, assessment_scores.score FROM users INNER JOIN assessment_scores ON users.id = assessment_scores.user_id")
    results = cursor.fetchall()
    conn.close()
    return results


# Run the database initialization
if __name__ == "__main__":
    init_db()
    print("Database initialized successfully!")
