from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt 


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///test.db'
db=SQLAlchemy(app)
bcrypt= Bcrypt(app)
app.config['SECRET_KEY']='Dronemake2021'
app.app_context().push()


login_manger=LoginManager()
login_manger.init_app(app)
login_manger.login_view="login"

@login_manger.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id=db.Column(db.Integer, primary_key=True)
    user_name=db.Column(db.String(40), nullable=False, unique=True)
    password=db.Column(db.String(80), nullable=False)

class RegisterForm(FlaskForm):
    user_name=StringField(validators=[InputRequired(), Length(min=4, max=30)],
                          render_kw={"placeholder": "Username"})
    password=PasswordField(validators=[InputRequired(), Length(min=8, max=20)],
                          render_kw={"placeholder": "Password"})
    submit=SubmitField("Register")
    
    def validate_username(self, user_name):
        existing_user_username=User.query.filter_by(User.user_name==user_name).fisrt()
        if existing_user_username:
            raise ValidationError(
                "This username already exists. Please enter a different one."
            )

class LoginForm(FlaskForm):
    user_name=StringField(validators=[InputRequired(), Length(min=4, max=30)],
                          render_kw={"placeholder": "Username"})   
    password=PasswordField(validators=[InputRequired(), Length(min=8, max=20)],
                          render_kw={"placeholder": "Password"})
    submit=SubmitField("Login")


class Todo(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    task_id=db.Column(db.String(40))
    content=db.Column(db.String(200), nullable=False)
    status=db.Column(db.String(30), default='In Progress')
    date_created=db.Column(db.DateTime, default=datetime.now(timezone.utc))
    
    def __repr__(self):
        return '<Task %r>' % self.id


@app.route('/')
def home():
    return render_template('home.html')
    
@app.route('/login',methods=['GET','POST'])
def login():
    global tid
    if request.method=='POST':
        tid=request.form['user_name']
    form=LoginForm()
    if form.validate_on_submit():
        user=User.query.filter_by(user_name=form.user_name.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('index'))

    return render_template('login.html',form=form)

@app.route('/logout',methods=['GET','POST'])
@login_required
def logout():
    logout_user
    return redirect(url_for('home'))

@app.route('/register',methods=['GET','POST'])
def register():
    form=RegisterForm()
    
    if form.validate_on_submit():
        hashed_password=bcrypt.generate_password_hash(form.password.data)
        new_user=User(user_name=form.user_name.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    
    return render_template('register.html',form=form)


@app.route("/index",methods=['POST','GET'])
def index():
    global tid
    if request.method=='POST':
        task_content=request.form['content']
        new_task=Todo(content=task_content,task_id=tid)
        try:
            db.session.add(new_task)
            db.session.commit()
            return redirect(url_for('index'))
        except:
            return "There was a problem in adding your task."
            
    else:
        tasks=Todo.query.order_by(Todo.date_created).filter(Todo.task_id==tid).all()
        return render_template('index.html',tasks=tasks)
        
@app.route('/delete/<int:id>')
def delete(id):
    task_to_delete=Todo.query.get_or_404(id)
    try:
        db.session.delete(task_to_delete)
        db.session.commit()
        return redirect(url_for('index'))
    except:
        return "There was a problem deleting that task."

@app.route('/update/<int:id>',methods=['GET','POST'])
def update(id):
    task=Todo.query.get_or_404(id)
    if request.method=='POST':
        task.content=request.form['content']
        task.status='In Progress'
        try:
            db.session.commit()
            return redirect(url_for('index'))
        except:
            return 'There was an issue updating your task.'
    else:
        return render_template('update.html', task=task)

@app.route('/complete/<int:id>',methods=['POST','GET'])
def complete(id):
    task_to_complete=Todo.query.get_or_404(id)
    task_to_complete.status='Completed'
    try:
        db.session.commit()
        return redirect(url_for('index'))
    except:
        return "There was an error in changing the status of your task."

    
if __name__=="__main__":
    app.run(debug=True)