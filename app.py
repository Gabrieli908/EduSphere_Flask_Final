from flask import Flask, render_template, redirect, url_for, flash, request
from flask import Flask, render_template, redirect, url_for, flash, request
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from forms import RegisterForm, LoginForm, InfoForm
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

from models import User, Info

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash("Username already exists.")
            return redirect(url_for("signup"))
        hashed_pw = generate_password_hash(form.password.data)
        user = User(username=form.username.data, password=hashed_pw, is_admin=form.is_admin.data)
        db.session.add(user)
        db.session.commit()
        flash("Registered successfully.")
        return redirect(url_for("login"))
    return render_template("signup.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for("submit_info"))
        flash("Invalid credentials.")
    return render_template("login.html", form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))

@app.route("/submit", methods=["GET", "POST"])
@login_required
def submit_info():
    form = InfoForm()
    if form.validate_on_submit():
        new_info = Info(title=form.title.data, content=form.content.data, user_id=current_user.id)
        db.session.add(new_info)
        db.session.commit()
        flash("Information submitted!")
        return redirect(url_for("view_info"))
    return render_template("submit.html", form=form)

@app.route("/info")
@login_required
def view_info():
    infos = Info.query.all()
    return render_template("info.html", infos=infos)

@app.route("/admin")
@login_required
def admin():
    if not current_user.is_admin:
        flash("Admins only!")
        return redirect(url_for("index"))
    users = User.query.all()
    return render_template("admin.html", users=users)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
