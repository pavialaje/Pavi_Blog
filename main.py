from datetime import date
from flask import Flask, render_template, redirect, url_for, flash, abort
from functools import wraps
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from forms import CreatePostForm, UserRegisterForm, LoginForm, CommentBox
from werkzeug.security import generate_password_hash, check_password_hash
from flask_gravatar import Gravatar

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = r'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

##temp user comment profile avatar
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


##CONFIGURE TABLES
# Creating user login database
class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(250))
    blogpost = db.relationship("BlogPost", back_populates="author")
    comments = db.relationship("Comment", back_populates="author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    author = db.relationship("User", back_populates="blogpost")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = db.relationship("Comment", back_populates="blog_post")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author = db.relationship("User", back_populates="comments")
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"), nullable=False)
    blog_post = db.relationship("BlogPost", back_populates="comments")
    text = db.Column(db.Text, nullable=False)


db.create_all()


@app.route('/')
def home():
    # posts=db.session.query(BlogPost).filter(BlogPost.author_id).all()
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/register', methods=["GET", "POST"])
def register():
    form = UserRegisterForm()
    if form.validate_on_submit():
        email = form.email.data
        user_exist = User.query.filter_by(email=email).first()
        if user_exist:
            flash("Email already exist.Try to login.")
            return redirect(url_for("login"))
        else:
            password = form.password.data
            name = form.name.data
            hashed_password = generate_password_hash(password, "pbkdf2:sha256:100", salt_length=8)
            new_user = User(name=name, email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash("Please login to continue.")
            return redirect(url_for("login"))
    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user_present = User.query.filter_by(email=email).first()
        if user_present and check_password_hash(user_present.password, password):
            login_user(user_present)
            return redirect(url_for("home"))
        else:
            flash("Please check your password and email.")
            return redirect(url_for('login'))
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


def admin_only(function):
    @wraps(function)
    def is_admin(*args, **kwargs):
        if current_user.get_id() != '1':
            abort(403, description="You are not authorized to access this page.")
        return function(*args, **kwargs)  # if user not admin return else with statement.

    is_admin.__name__ = function.__name__
    return is_admin


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    comment = CommentBox()
    requested_post = BlogPost.query.get(post_id)
    if comment.validate_on_submit():
        if current_user.is_anonymous:
            flash("Please login or Register to add your commnets.")
            return redirect(url_for("login"))
        add_comment = Comment(text=comment.box.data, author_id=current_user.get_id(), post_id=post_id)
        db.session.add(add_comment)
        db.session.commit()
    return render_template("post.html", post=requested_post, comment=comment)


@app.route("/about")
def about():
    return render_template("about.html",current_user=current_user)


@app.route("/contact")
def contact():
    return render_template("contact.html",current_user=current_user)


@app.route("/new-post", methods=['GET', 'POST'])
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
            date=date.today().strftime("%B %d, %Y"),
            author_id=current_user.get_id()

        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("home"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
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
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('home'))


if __name__ == "__main__":
    app.run(debug=True)
