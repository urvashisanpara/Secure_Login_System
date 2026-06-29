from flask import Flask,render_template,redirect,url_for,flash,session,request

from config import Config

from models import db,User

from forms import RegisterForm,LoginForm

from auth import bcrypt

from flask_login import LoginManager,login_user,logout_user,login_required,current_user

import pyotp

import qrcode

import os

app=Flask(__name__)

app.config.from_object(Config)

db.init_app(app)

bcrypt.init_app(app)

login_manager=LoginManager()

login_manager.init_app(app)

login_manager.login_view="login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register",methods=["GET","POST"])
def register():

    form=RegisterForm()

    if form.validate_on_submit():

        if User.query.filter_by(email=form.email.data).first():
            flash("Email already exists")
            return redirect(url_for("register"))

        hashed=bcrypt.generate_password_hash(
            form.password.data).decode("utf-8")

        secret=pyotp.random_base32()

        user=User(
            username=form.username.data,
            email=form.email.data,
            password=hashed,
            secret=secret
        )

        db.session.add(user)

        db.session.commit()

        uri=pyotp.TOTP(secret).provisioning_uri(
            name=form.email.data,
            issuer_name="SecureLogin"
        )

        img=qrcode.make(uri)

        os.makedirs("qr_codes",exist_ok=True)

        img.save("qr_codes/"+form.email.data+".png")

        flash("Registration Successful")

        return redirect(url_for("login"))

    return render_template("register.html",form=form)

@app.route("/login",methods=["GET","POST"])
def login():

    form=LoginForm()

    if form.validate_on_submit():

        user=User.query.filter_by(email=form.email.data).first()

        if user and bcrypt.check_password_hash(user.password,form.password.data):

            session["temp"]=user.id

            return redirect(url_for("verify"))

        flash("Invalid Login")

    return render_template("login.html",form=form)

@app.route("/verify",methods=["GET","POST"])
def verify():

    if request.method=="POST":

        otp=request.form["otp"]

        user=User.query.get(session["temp"])

        totp=pyotp.TOTP(user.secret)

        if totp.verify(otp):

            login_user(user)

            session.pop("temp")

            return redirect(url_for("dashboard"))

        flash("Invalid OTP")

    return render_template("verify.html")

@app.route("/dashboard")
@login_required
def dashboard():

    return render_template("dashboard.html")

@app.route("/logout")
@login_required
def logout():

    logout_user()

    return redirect(url_for("login"))

if __name__=="__main__":
    app.run(debug=True)