from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, create_access_token
from flask_cors import CORS
import bcrypt
import mysql.connector
import threading
import time

from dotenv import load_dotenv
import os
 
load_dotenv()

app = Flask(__name__)
CORS(app)
app.config['JWT_SECRET_KEY'] = 'abhishek_harsh_manish'
jwt = JWTManager(app)

def get_db_connection():
    """Establish and return a MySQL database connection with SSL."""
    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME"),
        port=int(os.getenv("DB_PORT"))
    )

# def verifyToken():
#     username = get_jwt_identity()
#     conn = get_db_connection()
#     cursor = conn.cursor(dictionary=True)
#     cursor.execute("SELECT COUNT(*) FROM users WHERE username = %s", (username,))
#     user_exists = cursor.fetchone()['COUNT(*)'] > 0
#     cursor.close()
#     conn.close()
#     return user_exists

@app.route('/api/login', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    
    if not username or not password:
        return jsonify({"msg": "Username and password are required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT hashed_password FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if user and bcrypt.checkpw(password.encode('utf-8'), user['hashed_password'].encode('utf-8')):
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"msg": "Bad username or password"}), 401


@app.route('/api/routes', methods=['GET'])
def get_routes():
    """Fetch API routes from the database."""
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT path, methods FROM api_routes")
    routes = cursor.fetchall()
    
    for route in routes:
        route['methods'] = route['methods'].split(', ')
    
    cursor.close()
    conn.close()
    return jsonify(routes)

@app.route('/api/vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    """Fetch vulnerabilities from the database."""
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT vulnerability_type, route_name FROM vulnerabilities")
    vulnerabilities = cursor.fetchall()
    cursor.close()
    conn.close()

    grouped_vulnerabilities = {}
    for vuln in vulnerabilities:
        vuln_type = vuln['vulnerability_type']
        if vuln_type not in grouped_vulnerabilities:
            grouped_vulnerabilities[vuln_type] = []
        grouped_vulnerabilities[vuln_type].append(vuln['route_name'])

    return jsonify(grouped_vulnerabilities)

@app.route('/api/vulnerabilities/<path:path>', methods=['GET'])
def get_vulnerability_details(path):
    """Fetch vulnerabilities for a specific API route from the database."""
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT vulnerability_type FROM vulnerabilities WHERE route_name = %s", (path,))
    vulnerabilities = cursor.fetchall()
    cursor.close()
    conn.close()

    route_vulnerabilities = {vuln['vulnerability_type']: path for vuln in vulnerabilities}
    return jsonify(route_vulnerabilities)


@app.route('/api/total_apis', methods=['GET'])
def get_total_apis():
    """Fetch total number of APIs from the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM api_routes")
    total_apis = cursor.fetchone()[0]
    cursor.close()
    conn.close()
    return jsonify(total_apis)

@app.route('/api/total_vulnerabilities', methods=['GET'])
def get_total_vulnerabilities():
    """Fetch total number of vulnerabilities from the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
    total_vulnerabilities = cursor.fetchone()[0]
    cursor.close()
    conn.close()
    return jsonify(total_vulnerabilities)

@app.route('/api/vulnerabilities/severity', methods=['GET'])
def get_vulnerabilities_severity():
    """Fetch severity of vulnerabilities from the database."""
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT vulnerability_type, severity_score as count FROM vulnerability_severity
    """)
    severity_data = cursor.fetchall()
    cursor.close()
    conn.close()

    severity_map = {
        'Critical': 4,
        'High': 3,
        'Medium': 2,
        'Low': 1
    }

    severity = {}
    for item in severity_data:
        vulnerability = item['vulnerability_type']
        count = item['count']
        severity_level = severity_map.get(vulnerability, 1)
        severity[vulnerability] = severity_level * count

    return jsonify(severity)

@app.route('/api/vulnerabilities/timeline', methods=['GET'])
def get_vulnerabilities_timeline():
    """Fetch the latest 15 entries of vulnerabilities from the live_graph table."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, vulnerabilities FROM live_graph ORDER BY id DESC LIMIT 15")
    timeline_data = cursor.fetchall()
    timeline_data.reverse()  
    cursor.close()
    conn.close()
    return jsonify(timeline_data)

@app.route('/api/code_score', methods=['GET'])
def get_code_score():
    """Fetch a calculated score of code quality from the database based on the severity and type of vulnerabilities."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
 
    cursor.execute("""
        SELECT vs.severity_score, COUNT(*) AS count
        FROM vulnerabilities v
        JOIN vulnerability_severity vs ON v.vulnerability_type = vs.vulnerability_type
        GROUP BY vs.severity_score
    """)    
    vulnerabilities = cursor.fetchall()

 
    total_impact = sum(score * count for score, count in vulnerabilities)

  
    cursor.execute("SELECT COUNT(*) FROM api_routes")
    total_apis = cursor.fetchone()[0]

   
    base_score = 100
    score_per_api = 10
    raw_score = score_per_api * total_apis - total_impact
    code_score = max(0, raw_score)

    cursor.close()
    conn.close()

    # return jsonify(formatted_score)

    
    if total_apis > 0:
        normalized_impact = (total_impact / total_apis) * 10
    else:
        normalized_impact = 0

    
    base_score = 100
    code_score = max(0, base_score - normalized_impact)

   
    code_score = f"{code_score:.2f}"

    return jsonify(code_score)


def insert_vulnerability_count():
    """Periodically check and update the total number of vulnerabilities in the live_graph table only if the count has changed."""
    last_vulnerability_count = None 

    while True:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
        current_vulnerability_count = cursor.fetchone()[0]
        print(f"Current vulnerability count: {current_vulnerability_count}")

       
        if last_vulnerability_count is None or current_vulnerability_count != last_vulnerability_count:
            print(f"Updating live graph: New count is {current_vulnerability_count}")
            
            
            cursor.execute("INSERT INTO live_graph (vulnerabilities) VALUES (%s)", (current_vulnerability_count,))
            conn.commit()
            
        
            last_vulnerability_count = current_vulnerability_count
        else:
            print("No change in vulnerability count; not updating live graph.")

        cursor.close()
        conn.close()

       
        time.sleep(5)

@app.route('/api/donought_chart', methods=['GET'])
def get_donought_chart():
    """Fetch counts of APIs affected by different severity levels of vulnerabilities."""
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

   
    cursor.execute("""
        SELECT vs.severity_level, vs.severity_score, COUNT(v.route_name) AS count
        FROM vulnerabilities v
        JOIN vulnerability_severity vs ON v.vulnerability_type = vs.vulnerability_type
        GROUP BY vs.severity_level, vs.severity_score
        ORDER BY vs.severity_score;

        # SELECT vs.severity_level, COUNT(v.route_name) AS count
        # FROM vulnerabilities v
        # JOIN vulnerability_severity vs ON v.vulnerability_type = vs.vulnerability_type
        # GROUP BY vs.severity_level ORDER BY vs.severity_score
    """)
    data = cursor.fetchall()
    print(data)
    cursor.close()
    conn.close()

    
    severity_counts = {item['severity_level']: item['count'] for item in data}
    return jsonify(severity_counts)



if __name__ == '__main__':
    
    # threading.Thread(target=insert_vulnerability_count, daemon=True).start()
    threading.Thread(daemon=True).start()

    app.run(debug=True, host='0.0.0.0', port=5001)  
