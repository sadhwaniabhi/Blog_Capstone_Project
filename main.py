import os
from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from functools import wraps
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentsForm
from flask_gravatar import Gravatar

# ----------- Flask app creation and configuration --------- #
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)

# ----------- Gravatar Configurations ---------------------- #
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


# ----------- Login Manager ---------------------- #
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ----------- Connection to DB ---------------------- #

# here env variable database_url is used to use postgresql provided by heroku, and blog.db is provided incase database_url doesn't work during local development
# newer versions of sqlalchemy has removed the support for "postgres://" uri scheme for postgresql database
database_uri = os.environ.get("DATABASE_URL", "sqlite:///blog.db" )
if database_uri.startswith("postgres://"):
    database_uri = database_uri.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# ----------- Database tables ---------------------- #
class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250))
    email = db.Column(db.String(250), unique=True)
    password = db.Column(db.String(100))
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comments", back_populates="comment_author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    # foreignkey in created to establish an relationship between users and blogpost table, here user.id passes the id of the user
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    # a reference to user object is created
    # back_populates is used to represent an additional relationship
    author = relationship('User', back_populates="posts")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comments", back_populates="parent_post")


class Comments(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)

    # relationship with user table
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    comment_author = relationship("User", back_populates="comments")

    # relationship with blog_posts table
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")

    text = db.Column(db.Text, nullable=False)


# we run this command only once to create database
db.create_all()


# ------- admin_login decorator ------------- #
def admin_login(f):
    """checks for admin user"""
    @wraps(f)
    def wrapper(*args,**kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args,**kwargs)
    return wrapper


# --------------- Functions --------------- #

@app.route('/')
def get_all_posts():
    """Function to display all post on the index page"""
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    """function to register new user"""
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data
        if User.query.filter_by(email=email).first():
            flash("User with this email already exist! Please Login.")
            return redirect(url_for("login"))

        hashed_password = generate_password_hash(password=form.password.data,
                                                 method="pbkdf2:sha256",
                                                 salt_length=8
                                                 )

        new_user = User(name=form.name.data,
                        email=email,
                        password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    """Login function ....gets data from the login form and checks email and password if they exist and are correct and gets user logged in"""
    form=LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for("get_all_posts"))
            else:
                flash("Invalid Password!")
                return redirect(url_for("login"))
        else:
            flash("User with that email does not exist! First register yourself with that email.")
            return redirect(url_for("login"))

    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    """loges out user"""
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    """Function to show details of each blog and accept comments from user and save them to database"""
    requested_post = BlogPost.query.get(post_id)
    form = CommentsForm()
    if form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comments(comment_author=current_user,
                                   parent_post=requested_post,
                                   text=form.comment.data
                                   )
            db.session.add(new_comment)
            db.session.commit()

        else:
            flash("For submitting a comment, Please Login.")
            return redirect(url_for("login"))
    return render_template("post.html", post=requested_post, form=form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@login_required
@admin_login
def add_new_post():
    """function to add new blogs, and it can only be accessed by admin user"""
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
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@login_required
@admin_login
def edit_post(post_id):
    """function to edit a blog, admin user required to access it"""
    post = BlogPost.query.get(post_id)
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
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_login
def delete_post(post_id):
    """function to delete a blog from the database"""
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))

# -------------------------------------------------------- #
if __name__ == "__main__":
    app.run(debug=True)
