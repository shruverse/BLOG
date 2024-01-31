from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
from sqlalchemy import func, desc
import os

# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm, ChangePasswordForm, SearchForm, ChangeEmailForm, ChangeUsernameForm, SuggestPostForm

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap5(app)

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy()
db.init_app(app)


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    # Create Foreign Key, "users.id" the users refers to the tablename of User.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    # Create reference to the User object. The "posts" refers to the posts property in the User class.
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    # Parent relationship to the comments
    comments = relationship("Comment", back_populates="parent_post")


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    profile_picture = db.Column(db.String(250))
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")


class Suggestions(db.Model):
    __tablename__ = "suggestions"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), nullable=False)
    reason = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)


with app.app_context():
    db.create_all()


# Create an admin-only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)

    return decorated_function


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        result = db.session.execute(db.select(User).where(User.email == form.email.data))
        user = result.scalar()
        if user:
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=form.email.data,
            name=form.name.data,
            password=hash_and_salted_password,
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=form, current_user=current_user)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        password = form.password.data
        result = db.session.execute(db.select(User).where(User.email == form.email.data))
        # Note, email in db is unique so will only have one result.
        user = result.scalar()
        # Email doesn't exist
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        # Password incorrect
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('get_all_posts'))

    return render_template("login.html", form=form, current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.context_processor
def header():
    form = SearchForm()
    return dict(form=form)


@app.route('/search', methods=['POST'])
def search():
    form = SearchForm()
    posts = BlogPost.query
    if form.validate_on_submit():
        searched_term = form.searched.data
        if searched_term:
            posts = posts.filter(BlogPost.body.like('%' + searched_term + '%'))
            posts = posts.order_by(BlogPost.title).all()
        else:
            posts = []
        return render_template('search.html', form=form, searched=searched_term, posts=posts)
    return render_template('search.html', form=form, searched=None, posts=None)


@app.route('/account', methods=["GET", "POST"])
@login_required
def account():
    change_password_form = ChangePasswordForm()
    if change_password_form.validate_on_submit():
        user = db.session.get(User, current_user.id)
        if user and check_password_hash(user.password, change_password_form.current_password.data):
            if change_password_form.new_password.data == change_password_form.confirm_new_password.data:
                user.password = generate_password_hash(change_password_form.new_password.data, method='pbkdf2:sha256',
                                                       salt_length=8)
                db.session.commit()
                flash("Password changed successfully!")
                return redirect(url_for('account'))
            else:
                flash("New passwords don't match. Please try again.")
        else:
            flash("Incorrect current password. Please try again.")
    user = db.session.get(User, current_user.id)
    return render_template("account.html", change_password_form=change_password_form, current_user=current_user, user=user)


@app.route('/upload-profile-picture', methods=['POST'])
@login_required
def upload_profile_picture():
    if 'profile_picture' in request.files:
        profile_picture = request.files['profile_picture']
        if profile_picture.filename != '':
            # Save the uploaded file to a specific directory (e.g., 'static/profile_pics')
            profile_picture.save(os.path.join(app.root_path, 'static/profile_pics', profile_picture.filename))

            # Update the current user's profile picture field with the file name or link
            current_user.profile_picture = profile_picture.filename  # Or store the file path as needed
            db.session.commit()
            flash('Profile picture updated successfully!')
    return redirect(url_for('account'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts, current_user=current_user)


@app.route("/all-posts")
def all_posts():
    post_per_page = 12
    page = int(request.args.get('page', 1))
    start = (page - 1) * post_per_page
    end = start + post_per_page
    total_posts = db.session.query(db.func.count(BlogPost.id)).scalar()
    num_pages = (total_posts + post_per_page - 1) // post_per_page
    result = db.session.query(BlogPost).order_by(desc(BlogPost.id)).slice(start, end)
    posts = result.all()
    return render_template("all-posts.html", all_posts=posts, current_user=current_user, page=page, num_pages=num_pages)


# Add a POST method to be able to post comments
@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    # Add the CommentForm to the route
    comment_form = CommentForm()
    # Only allow logged-in users to comment on posts
    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))

        new_comment = Comment(
            text=comment_form.comment_text.data,
            comment_author=current_user,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
    return render_template("post.html", post=requested_post, current_user=current_user, form=comment_form)


# Use a decorator so only an admin user can create new posts
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
    return render_template("admin/make-post.html", form=form, current_user=current_user)


# Use a decorator so only an admin user can edit a post
@app.route("/admin/edit-post/<int:post_id>", methods=["GET", "POST"])
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
    return render_template("admin/make-post.html", form=edit_form, is_edit=True, current_user=current_user)


@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user)


@app.route("/contact")
def contact():
    return render_template("contact.html", current_user=current_user)


@app.route("/admin/dashboard")
def dashboard():
    total_posts = db.session.query(func.count(BlogPost.id)).scalar()
    total_users = db.session.query(func.count(User.id)).scalar()
    total_comments = db.session.query(func.count(Comment.id)).scalar()
    total_suggestions = db.session.query(func.count(Suggestions.id)).scalar()
    return render_template("admin/dashboard.html", total_posts=total_posts, total_users=total_users, total_comments=total_comments, total_suggestions=total_suggestions)


@app.route("/admin/posts")
def posts_table():
    posts_per_page = 10
    page = int(request.args.get('page', 1))
    start = (page - 1) * posts_per_page
    end = start + posts_per_page
    total_posts = db.session.query(db.func.count(BlogPost.id)).scalar()
    num_pages = (total_posts + posts_per_page - 1) // posts_per_page
    result = db.session.query(BlogPost).order_by(desc(BlogPost.id)).slice(start, end)
    posts = result.all()
    return render_template("admin/posts-table.html", all_posts=posts, page=page, num_pages=num_pages)


@app.route("/admin/users")
def users_table():
    users_per_page = 10
    page = int(request.args.get('page', 1))
    start = (page - 1) * users_per_page
    end = start + users_per_page
    total_users = db.session.query(db.func.count(User.id)).scalar()
    num_pages = (total_users + users_per_page - 1) // users_per_page
    result = db.session.query(User).order_by(desc(User.id)).slice(start, end)
    users = result.all()
    return render_template("admin/users-table.html", users=users, page=page, num_pages=num_pages)


@app.route("/admin/comments")
def comments_table():
    comments_per_page = 10
    page = int(request.args.get('page', 1))
    start = (page - 1) * comments_per_page
    end = start + comments_per_page
    total_comments = db.session.query(db.func.count(Comment.id)).scalar()
    num_pages = (total_comments + comments_per_page - 1) // comments_per_page
    result = db.session.query(Comment).order_by(desc(Comment.id)).slice(start, end)
    comments = result.all()
    return render_template("admin/comments-table.html", comments=comments, page=page, num_pages=num_pages)


@app.route("/admin/suggestions")
@admin_only
def suggestions_table():
    suggestions_per_page = 10
    page = int(request.args.get('page', 1))
    start = (page - 1) * suggestions_per_page
    end = start + suggestions_per_page
    total_suggestions = db.session.query(db.func.count(Suggestions.id)).scalar()
    num_pages = (total_suggestions + suggestions_per_page - 1) // suggestions_per_page
    result = db.session.query(Suggestions).order_by(desc(Suggestions.id)).slice(start, end)
    suggestions = result.all()
    return render_template("admin/suggestions-table.html", suggestions=suggestions, page=page, num_pages=num_pages)


@app.route("/admin/delete-user/<int:user_id>")
@admin_only
def delete_user(user_id):
    user_to_delete = db.get_or_404(User, user_id)
    db.session.delete(user_to_delete)
    db.session.commit()
    flash("User deleted successfully!")
    result = db.session.execute(db.select(User))
    all_users = result.scalars().all()
    return render_template("admin/users-table.html", users=all_users)


@app.route("/admin/delete_comment/<int:comment_id>")
def delete_comment(comment_id):
    comment_to_delete = db.get_or_404(Comment, comment_id)
    db.session.delete(comment_to_delete)
    db.session.commit()
    flash("Comment deleted successfully!")
    result_comments = db.session.execute(db.select(Comment))
    all_comments = result_comments.scalars().all()
    return render_template("admin/comments-table.html", comments=all_comments)


@app.route("/admin/delete-post/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    flash("Post deleted successfully!")
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("admin/posts-table.html", all_posts=posts, page=1)


@app.route("/admin/delete-suggestion/<int:suggestion_id>")
@admin_only
def delete_suggestion(suggestion_id):
    suggestion_to_delete = db.get_or_404(Suggestions, suggestion_id)
    db.session.delete(suggestion_to_delete)
    db.session.commit()
    flash("Suggestion deleted successfully!")
    result = db.session.query(Suggestions).order_by(desc(Suggestions.id))
    suggestions = result.all()
    return render_template("admin/suggestions-table.html", suggestions=suggestions, page=1)


@app.route("/delete-account/<int:del_id>")
@login_required
def delete_account(del_id):
    if del_id == current_user.id:
        account_to_delete = User.query.get_or_404(del_id)
        db.session.delete(account_to_delete)
        logout()
        db.session.commit()
        flash("Account deleted successfully!")
        return redirect(url_for("get_all_posts"))


@app.route('/change-email', methods=["GET", "POST"])
@login_required
def change_email():
    change_email_form = ChangeEmailForm()
    if change_email_form.validate_on_submit():
        user = db.session.get(User, current_user.id)
        if user and check_password_hash(user.password, change_email_form.current_password.data):
            user.email = change_email_form.new_email.data
            db.session.commit()
            flash("Email changed successfully!")
            return redirect(url_for("account"))
        else:
            flash("Incorrect current password. Please try again.")
    user = db.session.get(User, current_user.id)
    return render_template("change-email.html", form=change_email_form, current_user=current_user, user=user)


@app.route('/change-username', methods=["GET", "POST"])
@login_required
def change_username():
    change_username_form = ChangeUsernameForm()
    if change_username_form.validate_on_submit():
        user = db.session.get(User, current_user.id)
        if user and check_password_hash(user.password, change_username_form.current_password.data):
            user.name = change_username_form.new_username.data
            db.session.commit()
            flash("Username changed successfully!")
            return redirect(url_for("account"))
        else:
            flash("Incorrect current password. Please try again.")
    user = db.session.get(User, current_user.id)
    return render_template("change-username.html", form=change_username_form, current_user=current_user, user=user)


@app.route('/suggest-post', methods=["GET", "POST"])
def suggest_post():
    suggest_form = SuggestPostForm()
    if suggest_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to suggest.")
            return redirect(url_for("login"))
        new_suggestion = Suggestions(
            title=suggest_form.title.data,
            reason=suggest_form.reason.data,
            body=suggest_form.body.data,
        )
        db.session.add(new_suggestion)
        db.session.commit()
        flash("Post suggestion submitted successfully, Thank you for your suggestions.")
        return redirect(url_for("get_all_posts"))
    return render_template("suggest-post.html", form=suggest_form, current_user=current_user)


if __name__ == "__main__":
    app.run(debug=True, port=5001)
