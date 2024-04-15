from datetime import datetime

from flask import Flask, render_template, flash, redirect, url_for, request
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, PasswordField, BooleanField, SubmitField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo
from flask_sqlalchemy import SQLAlchemy as _BaseSQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.urls import url_parse
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user, login_required
from functools import wraps
import re
from wtforms.fields import DateField

import pymysql
import secrets


conn = "mysql+pymysql://{0}:{1}@{2}/{3}".format(secrets.dbuser, secrets.dbpass, secrets.dbhost, secrets.dbname)

# Open database connection
#dbhost = secrets.dbhost
#dbuser = secrets.dbuser
#dbpass = secrets.dbpass
#dbname = secrets.dbname

#db = pymysql.connect(dbhost, dbuser, dbpass, dbname)

app = Flask(__name__)

login = LoginManager(app)
login.login_view = 'login'
login.login_message_category = 'danger' # sets flash category for the default message 'Please log in to access this page.'


app.config['SECRET_KEY']='SuperSecretKey'
# import os
# = os.environ.get('SECRET_KEY')


# Prevent --> pymysql.err.OperationalError) (2006, "MySQL server has gone away (BrokenPipeError(32, 'Broken pipe')
class SQLAlchemy(_BaseSQLAlchemy):
     def apply_pool_defaults(self, app, options):
        super(SQLAlchemy, self).apply_pool_defaults(app, options)
        options["pool_pre_ping"] = True
# <-- MWC


app.config['SQLALCHEMY_DATABASE_URI'] = conn
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # silence the deprecation warning
db = SQLAlchemy(app)


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')


class RegistrationForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')

class NewUserForm(FlaskForm):
    name = StringField('Name: ', validators=[DataRequired()])
    username = StringField('Username: ', validators=[DataRequired()])
    email = StringField('Email: ', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    access = IntegerField('Access: ')
    submit = SubmitField('Create User')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')

class WatchedVideo(db.Model):
    __tablename__ = 'watched_videos'

    id = db.Column(db.Integer, primary_key=True)
    video_id = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # Agregar user_id como un campo
    date_watched = db.Column(db.DateTime, nullable=False)

    def __init__(self, video_id, user_id, date_watched):
        self.video_id = video_id
        self.user_id = user_id  # Asignar el user_id proporcionado al atributo user_id de la instancia
        self.date_watched = date_watched

class UserDetailForm(FlaskForm):
    id = IntegerField('Id: ')
    name = StringField('Name: ', validators=[DataRequired()])
    username = StringField('Username: ', validators=[DataRequired()])
    email = StringField('Email: ', validators=[DataRequired(), Email()])
    access = IntegerField('Access: ')
    phone_number = db.Column(db.String(20))
    cause_of_amputation = db.Column(db.String(255))
    surgery_date = db.Column(db.Date)
    evaluation_date = db.Column(db.Date)


class AccountDetailForm(FlaskForm):
    id = IntegerField('Id: ')
    name = StringField('Name: ', validators=[DataRequired()])
    email = StringField('Email: ', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    phone_number = StringField('Phone Number: ', validators=[DataRequired()])  # Agregar este campo
    cause_of_amputation = StringField('Cause of Amputation: ', validators=[DataRequired()])
    surgery_date = DateField('Surgery Date: ', validators=[DataRequired()])
    evaluation_date = DateField('Evaluation Date: ', validators=[DataRequired()])


ACCESS = {
    'guest': 0,
    'user': 1,
    'admin': 2
}

class Video(db.Model):
    __tablename__ = 'Video'  # Añade esta línea para especificar el nombre de la tabla
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.String(255))
    url = db.Column(db.String(255))
    category = db.Column(db.String(255))
    status = db.Column(db.String(255))


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100))
    username = db.Column(db.String(30))
    password_hash = db.Column(db.String(128))
    access = db.Column(db.Integer)
    phone_number = db.Column(db.String(20))
    cause_of_amputation = db.Column(db.String(255))
    surgery_date = db.Column(db.Date)
    evaluation_date = db.Column(db.Date)

    def __init__(self, name, email, username, access=ACCESS['guest']):
        self.id = ''
        self.name = name
        self.email = email
        self.username = username
        self.password_hash = ''
        self.access = access

    def is_admin(self):
        return self.access == ACCESS['admin']

    def is_user(self):
        return self.access == ACCESS['user']

    def allowed(self, access_level):
        return self.access >= access_level

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<User {0}>'.format(self.username)




@login.user_loader
def load_user(id):
    return User.query.get(int(id))  #if this changes to a string, remove int

### custom wrap to determine access level ###
def requires_access_level(access_level):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated: #the user is not logged in
                return redirect(url_for('login'))

            #user = User.query.filter_by(id=current_user.id).first()

            if not current_user.allowed(access_level):
                flash('You do not have access to this resource.', 'danger')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator




#### Routes ####

# index
@app.route('/')
def index():
    return render_template('index.html', pageTitle='Flask App Home Page')

@app.route('/logros')
def logros():
    if current_user.is_authenticated:
        if current_user.is_admin():
            videos = Video.query.all()
            return render_template('logros_admin.html', pageTitle='logros Admin')

        else:
            videos = Video.query.all()
            return render_template('logros.html', pageTitle='logros')
    else:
        return redirect(url_for('login'))

#video
@app.route('/videos')
def videos():
    if current_user.is_authenticated:
        if current_user.is_admin():
            videos = Video.query.all()
            return render_template('videos_admin.html', pageTitle='Videos Admin', videos=videos)

        else:
            videos = Video.query.all()
            return render_template('video.html', pageTitle='Videos', videos=videos, extract_youtube_video_id=extract_youtube_video_id)
    else:
        return redirect(url_for('login'))

# about
@app.route('/about')
def about():
    return render_template('about.html', pageTitle='About My Flask App')


# registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(name=form.name.data, username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html',  pageTitle='Register | My Flask App', form=form)

# user login
# user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))  # Redirigir a dashboard si el usuario ya está autenticado
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('dashboard')  # Redirigir a dashboard si no hay una página de redireccionamiento específica
        flash('You are now logged in', 'success')
        return redirect(next_page)
    return render_template('login.html',  pageTitle='Login | My Flask App', form=form)



#logout
@app.route('/logout')
def logout():
    logout_user()
    flash('You have successfully logged out.', 'success')
    return redirect(url_for('index'))


################ GUEST ACCESS FUNCTIONALITY OR GREATER ###################

@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    user = User.query.get_or_404(current_user.id)
    form = AccountDetailForm()

    if form.validate_on_submit():
        user.name = form.name.data
        user.email = form.email.data
        user.phone_number = form.phone_number.data
        user.cause_of_amputation = form.cause_of_amputation.data
        user.surgery_date = form.surgery_date.data
        user.evaluation_date = form.evaluation_date.data
        user.set_password(form.password.data)

        db.session.commit()
        flash('Your account has been updated.', 'success')
        return redirect(url_for('account'))

    form.name.data = user.name
    form.email.data = user.email
    form.phone_number.data = user.phone_number
    form.cause_of_amputation.data = user.cause_of_amputation
    form.surgery_date.data = user.surgery_date
    form.evaluation_date.data = user.evaluation_date

    return render_template('account_detail.html', form=form, pageTitle='Your Account')



################ USER ACCESS FUNCTIONALITY OR GREATER ###################

# dashboard
@app.route('/dashboard')
@requires_access_level(ACCESS['user'])
def dashboard():
    return render_template('dashboard.html', pageTitle='My Flask App Dashboard')


################ ADMIN ACCESS FUNCTIONALITY ###################

# control panel
@app.route('/control_panel')
@requires_access_level(ACCESS['admin'])
def control_panel():
    all_users = User.query.all()
    return render_template('control_panel.html', users=all_users, pageTitle='My Flask App Control Panel')

# user details & update
@app.route('/user_detail/<int:user_id>', methods=['GET','POST'])
@requires_access_level(ACCESS['admin'])
def user_detail(user_id):
    user = User.query.get_or_404(user_id)
    form = UserDetailForm()
    form.id.data = user.id
    form.name.data = user.name
    form.email.data = user.email
    form.username.data = user.username
    form.access.data = user.access
    return render_template('user_detail.html', form=form, pageTitle='User Details')

# update user
@app.route('/update_user/<int:user_id>', methods=['POST'])
@requires_access_level(ACCESS['admin'])
def update_user(user_id):
    user = User.query.get_or_404(user_id)
    form = UserDetailForm()

    orig_user = user.username # get user details stored in the database - save username into a variable

    if form.validate_on_submit():
        user.name = form.name.data
        user.email = form.email.data

        new_user = form.username.data

        if new_user != orig_user: # if the form data is not the same as the original username
            valid_user = User.query.filter_by(username=new_user).first() # query the database for the usernam
            if valid_user is not None:
                flash("That username is already taken...", 'danger')
                return redirect(url_for('control_panel'))

        # if the values are the same, we can move on.
        user.username = form.username.data
        user.access = request.form['access_lvl']
        db.session.commit()
        flash('The user has been updated.', 'success')
        return redirect(url_for('control_panel'))

    return redirect(url_for('control_panel'))

# delete user
@app.route('/delete_user/<int:user_id>', methods=['POST'])
@requires_access_level(ACCESS['admin'])
def delete_user(user_id):
    if request.method == 'POST': #if it's a POST request, delete the friend from the database
        user = User.query.get_or_404(user_id)
        db.session.delete(user)
        db.session.commit()
        flash('User has been deleted.', 'success')
        return redirect(url_for('control_panel'))

    return redirect(url_for('control_panel'))

# new user
@app.route('/new_user', methods=['GET', 'POST'])
def new_user():
    form = NewUserForm()

    if request.method == 'POST' and form.validate_on_submit():
        user = User(name=form.name.data, username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        user.access = request.form['access_lvl']
        db.session.add(user)
        db.session.commit()
        flash('User has been successfully created.', 'success')
        return redirect(url_for('login'))

    return render_template('new_user.html',  pageTitle='New User | My Flask App', form=form)


@app.route('/add_video', methods=['POST'])
@requires_access_level(ACCESS['admin'])
def add_video():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        video_url = request.form['video_url']
        category = request.form['category']
        status = request.form['status']
        # Crear un nuevo objeto Video
        new_video = Video(name=name, description=description, url=video_url, category=category, status=status)  # Cambiar 'video' por 'url'
        # Añadir el objeto a la sesión
        db.session.add(new_video)
        try:
            # Intentar guardar en la base de datos
            db.session.commit()
            flash('Video added successfully!', 'success')
            return redirect(url_for('video'))
        except Exception as e:
            # Si ocurre un error, hacer un rollback y mostrar un mensaje de error
            db.session.rollback()
            flash(f'Error adding video: {str(e)}', 'danger')
            return redirect(url_for('video'))




@app.context_processor
def utility_processor():
    def generate_youtube_thumbnail(url):
        # Extraer el ID del video de la URL de YouTube
        video_id = re.findall(r'(?:https:\/\/)?(?:www\.)?(?:youtube\.com\/(?:[^\/\n\s]+\/\S+\/|(?:v|e(?:mbed)?)\/|\S*?[?&]v=)|youtu\.be\/)([a-zA-Z0-9_-]{11})', url)
        if video_id:
            # Devolver la URL de la miniatura de YouTube
            return f'https://img.youtube.com/vi/{video_id[0]}/0.jpg'
        else:
            return ''  # Manejar la URL del video incorrecta o no válida

    return dict(generate_youtube_thumbnail=generate_youtube_thumbnail)

def extract_youtube_video_id(url):
    # Expresión regular para extraer el ID del video de una URL de YouTube
    match = re.match(r'(?:https?:\/\/)?(?:www\.)?(?:youtube\.com\/(?:[^\/\n\s]+\/\S+\/|(?:v|e(?:mbed)?)\/|\S*?[?&]v=)|youtu\.be\/)([a-zA-Z0-9_-]{11})', url)
    if match:
        return match.group(1)
    else:
        return None

# Editar video
@app.route('/edit_video/<int:video_id>', methods=['GET', 'POST'])
@requires_access_level(ACCESS['admin'])
def edit_video(video_id):
    video = Video.query.get_or_404(video_id)
    form = VideoForm(obj=video)
    if form.validate_on_submit():
        form.populate_obj(video)
        db.session.commit()
        flash('Video updated successfully!', 'success')
        return redirect(url_for('videos'))
    return render_template('edit_video.html', pageTitle='Edit Video', form=form)

# Eliminar video
@app.route('/delete_video/<int:video_id>', methods=['POST'])
@requires_access_level(ACCESS['admin'])
def delete_video(video_id):
    video = Video.query.get_or_404(video_id)
    db.session.delete(video)
    db.session.commit()
    flash('Video deleted successfully!', 'success')
    return redirect(url_for('videos'))

@app.route('/watch_video', methods=['POST'])
def watch_video():
    if request.method == 'POST':
        data = request.json
        video_id = data.get('video_id')
        user_id = data.get('user_id')
        # Guardar el video visto y el usuario que lo vio en la base de datos
        if video_id and user_id:
            watched_video = WatchedVideo(video_id=video_id, user_id=user_id, date_watched=datetime.now())
            db.session.add(watched_video)
            db.session.commit()
            return 'OK', 200
        else:
            return 'Video ID or User ID missing in request', 400
    return 'Method Not Allowed', 405


if __name__ == '__main__':
    app.run(debug=True)
