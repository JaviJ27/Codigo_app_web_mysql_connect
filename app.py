from flask import Flask, render_template, request, redirect, url_for, session, flash
import pymysql
from functools import wraps
import os
import re

app = Flask(__name__)
app.secret_key = os.urandom(24)

DB_CONFIG = {
    'host': 'debiandb',
    'user': '',
    'password': '',
    'database': 'javierdb',
    'charset': 'utf8mb4',
    'cursorclass': pymysql.cursors.DictCursor
}

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Debes iniciar sesión primero', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_db_connection(user=None, password=None):
    config = DB_CONFIG.copy()
    if user and password:
        config['user'] = user
        config['password'] = password
    else:
        config['user'] = session.get('username', '')
        config['password'] = session.get('password', '')
    
    try:
        return pymysql.connect(**config)
    except pymysql.Error as e:
        return None

def validate_table_name(table_name):
    """Valida que el nombre de tabla sea seguro"""
    if not re.match(r'^[a-zA-Z0-9_]+$', table_name):
        return False
    return True

def sanitize_search(search):
    """Sanitiza el término de búsqueda para prevenir SQL injection"""
    if not search:
        return ""
    
    dangerous_chars = ["'", '"', ';', '--', '/*', '*/', 'DROP', 'DELETE', 'UPDATE', 
                      'INSERT', 'UNION', 'SELECT', 'FROM', 'WHERE', '=', '<', '>']
    search_lower = search.lower()
    for char in dangerous_chars:
        if char.lower() in search_lower:
            return ""
    return search

@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
                
        conn = get_db_connection(username, password)
        
        if conn:
            session['username'] = username
            session['password'] = password
            conn.close()
            flash(f'Bienvenido {username}!', 'success')
            return redirect(url_for('tables'))
        else:
            flash('Credenciales incorrectas', 'danger')
    
    return render_template('login.html')

@app.route('/tables')
@login_required
def tables():
    search = request.args.get('search', '')
    conn = get_db_connection()
    
    if not conn:
        flash('Error de conexión a la base de datos', 'danger')
        return redirect(url_for('login'))
    
    try:
        cursor = conn.cursor()
                
        if search:
            
            safe_search = sanitize_search(search)
            if not safe_search:
                flash('Término de búsqueda no válido', 'warning')
                safe_search = ""
                
            query = "SELECT table_name FROM information_schema.tables WHERE table_schema = %s AND table_name LIKE %s"
            cursor.execute(query, (DB_CONFIG['database'], f'%{safe_search}%'))
        else:
            query = "SELECT table_name FROM information_schema.tables WHERE table_schema = %s"
            cursor.execute(query, (DB_CONFIG['database'],))
        
        results = cursor.fetchall()
        
        tables_list = []
        for row in results:
            tables_list.append(row['table_name'])
        
        cursor.close()
        conn.close()
        
        return render_template('tables.html', tables=tables_list, search=search)
    
    except pymysql.Error as e:
        flash(f'Error: {str(e)}', 'danger')
        if conn:
            conn.close()
        return render_template('tables.html', tables=[], search=search)

@app.route('/table/<table_name>')
@login_required
def view_table(table_name):
    search = request.args.get('search', '')
        
    if not validate_table_name(table_name):
        flash('Nombre de tabla no válido', 'danger')
        return redirect(url_for('tables'))
    
    conn = get_db_connection()
    
    if not conn:
        flash('Error de conexión a la base de datos', 'danger')
        return redirect(url_for('login'))
    
    try:
        cursor = conn.cursor()
            
        check_query = "SELECT COUNT(*) as count FROM information_schema.tables WHERE table_schema = %s AND table_name = %s"
        cursor.execute(check_query, (DB_CONFIG['database'], table_name))
        result = cursor.fetchone()
        
        if result['count'] == 0:
            flash('La tabla no existe o no tienes permisos', 'danger')
            cursor.close()
            conn.close()
            return redirect(url_for('tables'))
        
        if search:
            safe_search = sanitize_search(search)
            if not safe_search:
                flash('Término de búsqueda no válido. No se permiten comandos SQL.', 'warning')
                cursor.close()
                conn.close()
                return render_template('table_view.html', 
                                     table_name=table_name, 
                                     columns=[], 
                                     rows=[], 
                                     search=search)
            
                
            query = f"SELECT * FROM `{table_name}` LIMIT 0"
            cursor.execute(query)
            columns = [desc[0] for desc in cursor.description] if cursor.description else []
            
            if columns:
                conditions = " OR ".join([f"`{col}` LIKE %s" for col in columns])
                query = f"SELECT * FROM `{table_name}` WHERE {conditions}"
                params = tuple([f'%{safe_search}%'] * len(columns))
                cursor.execute(query, params)
            else:
                query = f"SELECT * FROM `{table_name}`"
                cursor.execute(query)
        else:
            query = f"SELECT * FROM `{table_name}`"
            cursor.execute(query)
        
        results = cursor.fetchall()
        
        columns = []
        if cursor.description:
            columns = [desc[0] for desc in cursor.description]
        
        cursor.close()
        conn.close()
        
        return render_template('table_view.html', 
                             table_name=table_name, 
                             columns=columns, 
                             rows=results, 
                             search=search)
    
    except pymysql.Error as e:
        flash(f'Error: {str(e)}', 'danger')
        if conn:
            conn.close()
        return render_template('table_view.html', 
                             table_name=table_name, 
                             columns=[], 
                             rows=[], 
                             search=search)

@app.route('/logout')
def logout():
    session.clear()
    flash('Sesión cerrada correctamente', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
