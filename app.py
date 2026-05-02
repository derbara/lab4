from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin #авторизация
import mysql.connector
from mysql.connector import Error #обработка ошибок бд
import hashlib #для защиты паролей
import re #валидация данных
from datetime import datetime

app = Flask(__name__)
app.secret_key = '123'

login_manager = LoginManager() #управление логином
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Для доступа к этой странице необходимо войти в систему.'
login_manager.login_message_category = 'warning'


DB_CONFIG = {
    'host': 'localhost',
    'database': 'lab4_db',
    'user': 'root',
    'password': 'Yasya2006'
}

def get_db():
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn
    except Error as e:
        print("DB ERROR:", e)  # 👈 ВАЖНО
        return None

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

#класс юзера
class User(UserMixin):
    def __init__(self, id, login, last_name, first_name, middle_name, role_id, role_name):
        self.id = id
        self.login = login
        self.last_name = last_name
        self.first_name = first_name
        self.middle_name = middle_name
        self.role_id = role_id
        self.role_name = role_name

    @property
    def full_name(self): #если нет полного имени используется логин
        parts = [self.last_name or '', self.first_name or '', self.middle_name or '']
        return ' '.join(p for p in parts if p).strip() or self.login

@login_manager.user_loader #получение пользователя по айди
def load_user(user_id):
    conn = get_db()
    if not conn:
        return None
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT u.*, r.name as role_name 
            FROM users u 
            LEFT JOIN roles r ON u.role_id = r.id 
            WHERE u.id = %s
        """, (user_id,))
        row = cursor.fetchone()
        if row:
            return User(row['id'], row['login'], row['last_name'], row['first_name'],
                       row['middle_name'], row['role_id'], row.get('role_name'))
        return None
    finally:
        cursor.close()
        conn.close()

# валидация
def validate_login(login):
    if not login:
        return 'Поле не может быть пустым'
    if len(login) < 5:
        return 'Логин должен содержать не менее 5 символов'
    if not re.match(r'^[a-zA-Z0-9]+$', login):
        return 'Логин должен состоять только из латинских букв и цифр'
    return None

def validate_password(password):
    if not password:
        return 'Поле не может быть пустым'
    if len(password) < 8:
        return 'Пароль должен содержать не менее 8 символов'
    if len(password) > 128:
        return 'Пароль должен содержать не более 128 символов'
    if ' ' in password:
        return 'Пароль не должен содержать пробелы'
    if not re.search(r'[A-ZА-ЯЁ]', password):
        return 'Пароль должен содержать хотя бы одну заглавную букву'
    if not re.search(r'[a-zа-яё]', password):
        return 'Пароль должен содержать хотя бы одну строчную букву'
    if not re.search(r'[0-9]', password):
        return 'Пароль должен содержать хотя бы одну цифру'
    allowed = r'^[a-zA-Zа-яА-ЯёЁ0-9~!?@#$%^&*_\-+()\[\]{}<>/\\|"\'.,:;]+$'
    if not re.match(allowed, password):
        return 'Пароль содержит недопустимые символы'
    return None

def get_roles(): #получает список всех ролей и сортирует по имени
    conn = get_db()
    if not conn:
        return []
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM roles ORDER BY name")
        return cursor.fetchall()
    finally:
        cursor.close()
        conn.close()

# главная страница

@app.route('/')
def index():
    conn = get_db()
    users = []
    if conn:
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("""
                SELECT u.id, u.login, u.last_name, u.first_name, u.middle_name, r.name as role_name
                FROM users u
                LEFT JOIN roles r ON u.role_id = r.id
                ORDER BY u.id
            """)
            users = cursor.fetchall()
        finally:
            cursor.close()
            conn.close()
    return render_template('index.html', users=users)


@app.route('/login', methods=['GET', 'POST']) #страница входа
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        login_val = request.form.get('login', '').strip()
        password = request.form.get('password', '')
        
        conn = get_db()
        if not conn:
            flash('Ошибка подключения к базе данных', 'danger')
            return render_template('login.html')
        
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("""
                SELECT u.*, r.name as role_name 
                FROM users u 
                LEFT JOIN roles r ON u.role_id = r.id 
                WHERE u.login = %s AND u.password_hash = %s
            """, (login_val, hash_password(password)))
            row = cursor.fetchone() #для получения 1 строки
            
            if row:
                user = User(row['id'], row['login'], row['last_name'], row['first_name'],
                           row['middle_name'], row['role_id'], row.get('role_name'))
                login_user(user)
                flash('Вы успешно вошли в систему', 'success')
                next_page = request.args.get('next')
                return redirect(next_page or url_for('index'))
            else:
                flash('Неверный логин или пароль', 'danger')
        finally:
            cursor.close()
            conn.close()
    
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('index'))


@app.route('/users/<int:user_id>') #просмотр пользователя
def view_user(user_id):
    conn = get_db()
    if not conn:
        flash('Ошибка подключения к базе данных', 'danger')
        return redirect(url_for('index'))
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT u.*, r.name as role_name
            FROM users u
            LEFT JOIN roles r ON u.role_id = r.id
            WHERE u.id = %s
        """, (user_id,))
        user = cursor.fetchone()
        if not user:
            flash('Пользователь не найден', 'danger')
            return redirect(url_for('index'))
        return render_template('view_user.html', user=user)
    finally:
        cursor.close()
        conn.close()


@app.route('/users/create', methods=['GET', 'POST']) #создание пользователя
@login_required
def create_user():
    roles = get_roles()
    errors = {}
    form_data = {}

    if request.method == 'POST':
        form_data = {
            'login': request.form.get('login', '').strip(),
            'password': request.form.get('password', ''),
            'last_name': request.form.get('last_name', '').strip(),
            'first_name': request.form.get('first_name', '').strip(),
            'middle_name': request.form.get('middle_name', '').strip(),
            'role_id': request.form.get('role_id', '') or None,
        }

        # валидация
        login_err = validate_login(form_data['login'])
        if login_err:
            errors['login'] = login_err

        pwd_err = validate_password(form_data['password'])
        if pwd_err:
            errors['password'] = pwd_err

        if not form_data['first_name']:
            errors['first_name'] = 'Поле не может быть пустым'

        if errors:
            return render_template('user_form.html', roles=roles, errors=errors,
                                   form_data=form_data, mode='create')

        conn = get_db()
        if not conn:
            flash('Ошибка подключения к базе данных', 'danger')
            return render_template('user_form.html', roles=roles, errors=errors,
                                   form_data=form_data, mode='create')
        try:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO users (login, password_hash, last_name, first_name, middle_name, role_id, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                form_data['login'],
                hash_password(form_data['password']),
                form_data['last_name'] or None,
                form_data['first_name'],
                form_data['middle_name'] or None,
                form_data['role_id'],
                datetime.now()
            ))
            conn.commit()
            flash('Пользователь успешно создан', 'success')
            return redirect(url_for('index'))
        except Error as e:
            flash(f'Ошибка при сохранении: {e}', 'danger')
            return render_template('user_form.html', roles=roles, errors=errors,
                                   form_data=form_data, mode='create')
        finally:
            cursor.close()
            conn.close()

    return render_template('user_form.html', roles=roles, errors=errors,
                           form_data=form_data, mode='create')


@app.route('/users/<int:user_id>/edit', methods=['GET', 'POST']) #редактирование пользователя
@login_required
def edit_user(user_id):
    roles = get_roles()
    errors = {}

    conn = get_db()
    if not conn:
        flash('Ошибка подключения к базе данных', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        form_data = {
            'last_name': request.form.get('last_name', '').strip(),
            'first_name': request.form.get('first_name', '').strip(),
            'middle_name': request.form.get('middle_name', '').strip(),
            'role_id': request.form.get('role_id', '') or None,
        }

        if not form_data['first_name']:#валидация
            errors['first_name'] = 'Поле не может быть пустым'

        if errors:
            conn.close()
            return render_template('user_form.html', roles=roles, errors=errors,
                                   form_data=form_data, mode='edit', user_id=user_id)

        try:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE users SET last_name=%s, first_name=%s, middle_name=%s, role_id=%s
                WHERE id=%s
            """, (
                form_data['last_name'] or None,
                form_data['first_name'],
                form_data['middle_name'] or None,
                form_data['role_id'],
                user_id
            ))
            conn.commit()
            flash('Данные пользователя обновлены', 'success')
            return redirect(url_for('index'))
        except Error as e:
            flash(f'Ошибка при сохранении: {e}', 'danger')
            return render_template('user_form.html', roles=roles, errors=errors,
                                   form_data=form_data, mode='edit', user_id=user_id)
        finally:
            cursor.close()
            conn.close()

    # открытие пользователя
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
        user = cursor.fetchone()
        if not user:
            flash('Пользователь не найден', 'danger')
            return redirect(url_for('index'))
        form_data = {
            'last_name': user['last_name'] or '',
            'first_name': user['first_name'] or '',
            'middle_name': user['middle_name'] or '',
            'role_id': user['role_id'] or '',
        }
        return render_template('user_form.html', roles=roles, errors=errors,
                               form_data=form_data, mode='edit', user_id=user_id)
    finally:
        cursor.close()
        conn.close()


@app.route('/users/<int:user_id>/delete', methods=['POST']) #удаление пользователя
@login_required
def delete_user(user_id):
    conn = get_db()
    if not conn:
        flash('Ошибка подключения к базе данных', 'danger')
        return redirect(url_for('index'))
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE id=%s", (user_id,))
        conn.commit()
        flash('Пользователь удалён', 'success')
    except Error as e:
        flash(f'Ошибка при удалении: {e}', 'danger')
    finally:
        cursor.close()
        conn.close()
    return redirect(url_for('index'))


@app.route('/change-password', methods=['GET', 'POST']) #изменение пароля
@login_required
def change_password():
    errors = {}

    if request.method == 'POST':
        old_password = request.form.get('old_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        conn = get_db()
        if not conn:
            flash('Ошибка подключения к базе данных', 'danger')
            return render_template('change_password.html', errors=errors)

        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT password_hash FROM users WHERE id=%s", (current_user.id,))
            row = cursor.fetchone()

            if not row or row['password_hash'] != hash_password(old_password):
                errors['old_password'] = 'Неверный текущий пароль'

            pwd_err = validate_password(new_password)
            if pwd_err:
                errors['new_password'] = pwd_err

            if new_password != confirm_password:
                errors['confirm_password'] = 'Пароли не совпадают'

            if errors:
                return render_template('change_password.html', errors=errors)

            cursor.execute("UPDATE users SET password_hash=%s WHERE id=%s",
                          (hash_password(new_password), current_user.id))
            conn.commit()
            flash('Пароль успешно изменён', 'success')
            return redirect(url_for('index'))
        except Error as e:
            flash(f'Ошибка: {e}', 'danger')
        finally:
            cursor.close()
            conn.close()

    return render_template('change_password.html', errors=errors)


if __name__ == '__main__':
    app.run(debug=True)
