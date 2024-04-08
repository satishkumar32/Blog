from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text
from functools import wraps
from sqlalchemy import ForeignKey
from werkzeug.security import generate_password_hash, check_password_hash
# Import your forms from the forms.py
from forms import CreatePostForm, RegisterNewUser, LoginUser, UserComment
import os
from dotenv import load_dotenv

'''
Make sure the required packages are installed: 
Open the Terminal in PyCharm (bottom left). 

On Windows type:
python -m pip install -r requirements.txt

On MacOS type:
pip3 install -r requirements.txt

This will install the packages from the requirements.txt for this project.
'''
load_dotenv("osdata.env")
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("FLASK_KEY")
ckeditor = CKEditor(app)
Bootstrap5(app)
login_manager = LoginManager()
login_manager.init_app(app)
app.secret_key = os.environ.get("SECRET_KEY")


# TODO: Configure Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


# For adding profile images to the comment section
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


# CREATE DATABASE
class Base(DeclarativeBase):
    pass


app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI", "sqlite:///posts.db")
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# TODO: Create a User table for all your registered users. 
class User(UserMixin, db.Model):
    __tablename__ = "user"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comment = relationship("Comment", back_populates="comment_author")


# CONFIGURE TABLES
class BlogPost(UserMixin, db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("user.id"))
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    author = relationship("User", back_populates="posts")
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    comments = relationship("Comment", back_populates="parent_post")


class Comment(UserMixin, db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("user.id"))
    comment_author = relationship("User", back_populates="comment")
    post_id: Mapped[str] = mapped_column(Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")


with app.app_context():
    db.create_all()


# Create admin-only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)

    return decorated_function


# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterNewUser()
    if request.method == "POST":
        if form.validate_on_submit():
            form_password = request.form.get("password")
            password_hash = generate_password_hash(form_password, method="pbkdf2", salt_length=8)
            new_user = User(
                email=request.form.get("email"),
                password=password_hash,
                name=request.form.get("name").title()
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(user=new_user)
            return redirect("/")
    return render_template("register.html", form=form, logged_in=current_user.is_authenticated)


# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginUser()
    if request.method == "POST":
        if form.validate_on_submit():
            user_email = request.form.get("email")
            user_password = request.form.get("password")
            user_details = db.session.execute(db.select(User).filter_by(email=user_email)).scalar_one()
            hash_pass = check_password_hash(user_details.password, user_password)
            if user_email == user_details.email and hash_pass:
                login_user(user=user_details)
                return redirect("/")
            else:
                flash("Invalid email or password. Please try again.")
    return render_template("login.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = UserComment()
    requested_post = db.get_or_404(BlogPost, post_id)
    if request.method == "POST":
        if current_user.is_authenticated:
            new_comment = Comment(
                body=request.form.get("body"),
                comment_author=current_user,
                parent_post=requested_post
            )
            db.session.add(new_comment)
            db.session.commit()
            form.body.data = ''
            return render_template("post.html", post=requested_post, logged_in=current_user.is_authenticated, form=form)
        else:
            return redirect("/login")
    else:
        requested_post = db.get_or_404(BlogPost, post_id)
        return render_template("post.html", post=requested_post, logged_in=current_user.is_authenticated, form=form)

    # TODO: Use a decorator so only an admin user can create a new post


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user=current_user,
                           logged_in=current_user.is_authenticated)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True, current_user=current_user,
                           logged_in=current_user.is_authenticated)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=False, port=5002)
