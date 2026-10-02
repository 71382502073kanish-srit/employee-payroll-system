import os
import re
import secrets
from functools import wraps
from decimal import Decimal, InvalidOperation

from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "dev-only-change-me"),
    SQLALCHEMY_DATABASE_URI=os.environ.get("DATABASE_URL", "sqlite:///payroll.db").replace("postgres://", "postgresql://", 1),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "0") == "1",
)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(30), nullable=False, default="Employee")

class Employee(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.String(40), unique=True, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    department = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150))
    phone = db.Column(db.String(40))

class Payroll(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.String(40), nullable=False)
    basic_salary = db.Column(db.Numeric(12, 2), nullable=False)
    allowance = db.Column(db.Numeric(12, 2), nullable=False, default=0)
    deduction = db.Column(db.Numeric(12, 2), nullable=False, default=0)
    net_salary = db.Column(db.Numeric(12, 2), nullable=False)


def csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token

@app.context_processor
def inject_helpers():
    return {"csrf_token": csrf_token}

@app.before_request
def protect_post_requests():
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not expected or not secrets.compare_digest(sent, expected):
            abort(400, description="Invalid or missing CSRF token.")

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:;"
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


def init_db():
    with app.app_context():
        db.create_all()
        if User.query.count() == 0:
            username = os.environ.get("ADMIN_USERNAME", "admin").strip()
            password = os.environ.get("ADMIN_PASSWORD", "")
            if not password:
                if os.environ.get("DATABASE_URL", "").startswith(("postgresql://", "postgres://")):
                    raise RuntimeError("ADMIN_PASSWORD must be set for a cloud database deployment.")
                password = "ChangeMe_123!"
            db.session.add(User(username=username, password_hash=generate_password_hash(password), role="Administrator"))
            db.session.commit()


def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapped


def admin_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        if session.get("role") != "Administrator":
            flash("Administrator access is required.")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return wrapped

@app.route("/health")
def health():
    try:
        db.session.execute(db.text("SELECT 1"))
        return {"status": "ok", "database": "connected"}, 200
    except Exception:
        return {"status": "error", "database": "unavailable"}, 503

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session.clear()
            session["user_id"] = user.id
            session["user"] = user.username
            session["role"] = user.role
            session["csrf_token"] = secrets.token_urlsafe(32)
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
@login_required
def dashboard():
    emp = Employee.query.count()
    payroll_count = Payroll.query.count()
    total = db.session.query(db.func.coalesce(db.func.sum(Payroll.net_salary), 0)).scalar() or 0
    depts = db.session.query(Employee.department, db.func.count(Employee.id).label("n")).group_by(Employee.department).all()
    recent = Employee.query.order_by(Employee.id.desc()).limit(6).all()
    return render_template("dashboard.html", emp=emp, payroll=payroll_count, total=total, depts=depts, recent=recent)

@app.route("/employees", methods=["GET", "POST"])
@login_required
def employees():
    if request.method == "POST":
        employee_id = request.form.get("employee_id", "").strip()
        name = request.form.get("name", "").strip()
        department = request.form.get("department", "").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        if not employee_id or not name or not department:
            flash("Employee ID, name and department are required.")
        elif Employee.query.filter_by(employee_id=employee_id).first():
            flash("Employee ID already exists.")
        else:
            db.session.add(Employee(employee_id=employee_id, name=name, department=department, email=email, phone=phone))
            db.session.commit()
            flash("Employee added successfully.")
        return redirect(url_for("employees"))
    rows = Employee.query.order_by(Employee.id.desc()).all()
    return render_template("employees.html", employees=rows)

@app.route("/employees/delete/<int:i>", methods=["POST"])
@login_required
def delete_employee(i):
    employee = db.session.get(Employee, i)
    if employee:
        db.session.delete(employee)
        db.session.commit()
        flash("Employee deleted.")
    return redirect(url_for("employees"))

@app.route("/payroll", methods=["GET", "POST"])
@login_required
def payroll_page():
    if request.method == "POST":
        try:
            b = Decimal(request.form.get("basic", "0"))
            a = Decimal(request.form.get("allowance", "0"))
            d = Decimal(request.form.get("deduction", "0"))
            if b < 0 or a < 0 or d < 0:
                raise InvalidOperation
            employee_id = request.form.get("employee_id", "").strip()
            if not Employee.query.filter_by(employee_id=employee_id).first():
                flash("Select a valid employee.")
                return redirect(url_for("payroll_page"))
            db.session.add(Payroll(employee_id=employee_id, basic_salary=b, allowance=a, deduction=d, net_salary=b + a - d))
            db.session.commit()
            flash("Payroll saved.")
        except (InvalidOperation, ValueError):
            flash("Enter valid non-negative salary values.")
        return redirect(url_for("payroll_page"))
    emps = Employee.query.order_by(Employee.name).all()
    rows = db.session.query(Payroll, Employee.name.label("employee_name")).outerjoin(Employee, Payroll.employee_id == Employee.employee_id).order_by(Payroll.id.desc()).all()
    payroll_rows = [{"employee_id": p.employee_id, "name": name or p.employee_id, "basic_salary": p.basic_salary, "allowance": p.allowance, "deduction": p.deduction, "net_salary": p.net_salary} for p, name in rows]
    return render_template("payroll.html", employees=emps, payroll=payroll_rows)

@app.route("/naming", methods=["GET", "POST"])
@login_required
def naming():
    result = None
    suggestion = None
    original = ""
    if request.method == "POST":
        original = request.form.get("field_name", "").strip()
        valid = bool(re.fullmatch(r"[a-z][a-z0-9_]*", original)) and "__" not in original and not original.endswith("_")
        result = valid
        parts = re.findall(r"[A-Z]+(?=[A-Z][a-z]|\d|$)|[A-Z]?[a-z]+|\d+", original)
        suggestion = "_".join(x.lower() for x in parts) or "field_name"
    return render_template("naming.html", result=result, suggestion=suggestion, original=original)

@app.route("/reports")
@login_required
def reports():
    employees_list = Employee.query.order_by(Employee.name).all()
    rows = db.session.query(Payroll, Employee.name.label("employee_name")).outerjoin(Employee, Payroll.employee_id == Employee.employee_id).order_by(Payroll.id.desc()).all()
    payroll_rows = [{"employee_id": p.employee_id, "name": name or p.employee_id, "basic_salary": p.basic_salary, "allowance": p.allowance, "deduction": p.deduction, "net_salary": p.net_salary} for p, name in rows]
    return render_template("reports.html", employees=employees_list, payroll=payroll_rows)

@app.route("/admin", methods=["GET", "POST"])
@admin_required
def admin():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "Employee")
        if role not in {"Administrator", "HR", "Employee"}:
            role = "Employee"
        if len(username) < 3 or len(password) < 8:
            flash("Username must be at least 3 characters and password at least 8 characters.")
        elif User.query.filter_by(username=username).first():
            flash("Username already exists.")
        else:
            db.session.add(User(username=username, password_hash=generate_password_hash(password), role=role))
            db.session.commit()
            flash("User created successfully.")
        return redirect(url_for("admin"))
    users = User.query.order_by(User.username).all()
    return render_template("admin.html", users=users)

@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def delete_user(user_id):
    if user_id == session.get("user_id"):
        flash("You cannot delete your own account.")
        return redirect(url_for("admin"))
    user = db.session.get(User, user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash("User deleted.")
    return redirect(url_for("admin"))

with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)), debug=False)
