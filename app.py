import os, secrets, random, string
from datetime import datetime, date
from flask import Flask, render_template, request, redirect, url_for, flash, abort, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager, UserMixin, login_user, logout_user,
                         login_required, current_user)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
uri = os.environ.get("DATABASE_URL", "sqlite:///classyar.db")
if uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = uri
db = SQLAlchemy(app)
lm = LoginManager(app)
lm.login_view = "login"
lm.login_message = "برای ادامه وارد شوید."


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    pw = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # teacher | student


class Classroom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, default="")
    code = db.Column(db.String(8), unique=True)
    teacher_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    teacher = db.relationship("User")
    students = db.relationship("User", secondary="enrollment")


class Enrollment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    class_id = db.Column(db.Integer, db.ForeignKey("classroom.id"))


class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    class_id = db.Column(db.Integer, db.ForeignKey("classroom.id"))
    text = db.Column(db.Text, nullable=False)
    created = db.Column(db.DateTime, default=datetime.utcnow)


class Assignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    class_id = db.Column(db.Integer, db.ForeignKey("classroom.id"))
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, default="")
    due = db.Column(db.Date)
    classroom = db.relationship("Classroom")


class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    assignment_id = db.Column(db.Integer, db.ForeignKey("assignment.id"))
    student_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    text = db.Column(db.Text, nullable=False)
    grade = db.Column(db.Float)
    feedback = db.Column(db.Text, default="")
    created = db.Column(db.DateTime, default=datetime.utcnow)
    student = db.relationship("User")


class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    class_id = db.Column(db.Integer, db.ForeignKey("classroom.id"))
    student_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    day = db.Column(db.Date, nullable=False)
    present = db.Column(db.Boolean, default=True)


with app.app_context():
    db.create_all()


@lm.user_loader
def load_user(uid):
    return db.session.get(User, int(uid))


@app.before_request
def csrf_check():
    if request.method == "POST" and request.form.get("_csrf") != session.get("_csrf"):
        abort(400)


@app.context_processor
def inject():
    session.setdefault("_csrf", secrets.token_hex(16))
    return {"csrf": session["_csrf"]}


def get_class(cid):
    c = db.get_or_404(Classroom, cid)
    ok = current_user.id == c.teacher_id or current_user in c.students
    if not ok:
        abort(403)
    return c


def teacher_only(c):
    if current_user.id != c.teacher_id:
        abort(403)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        f = request.form
        email = f["email"].strip().lower()
        if len(f["password"]) < 6:
            flash("رمز عبور باید حداقل ۶ کاراکتر باشد.")
        elif User.query.filter_by(email=email).first():
            flash("این ایمیل قبلاً ثبت شده است.")
        else:
            role = "teacher" if f.get("role") == "teacher" else "student"
            u = User(name=f["name"].strip(), email=email, role=role,
                     pw=generate_password_hash(f["password"]))
            db.session.add(u)
            db.session.commit()
            login_user(u)
            return redirect(url_for("dashboard"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = User.query.filter_by(email=request.form["email"].strip().lower()).first()
        if u and check_password_hash(u.pw, request.form["password"]):
            login_user(u)
            return redirect(url_for("dashboard"))
        flash("ایمیل یا رمز عبور اشتباه است.")
    return render_template("login.html")


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.role == "teacher":
        classes = Classroom.query.filter_by(teacher_id=current_user.id).all()
    else:
        classes = Classroom.query.join(Enrollment).filter(
            Enrollment.user_id == current_user.id).all()
    return render_template("dashboard.html", classes=classes)


@app.route("/class/new", methods=["POST"])
@login_required
def class_new():
    if current_user.role != "teacher":
        abort(403)
    code = "".join(random.choices(string.ascii_uppercase + string.digits, k=6))
    c = Classroom(title=request.form["title"].strip(), code=code,
                  description=request.form.get("description", ""),
                  teacher_id=current_user.id)
    db.session.add(c)
    db.session.commit()
    return redirect(url_for("class_view", cid=c.id))


@app.route("/class/join", methods=["POST"])
@login_required
def class_join():
    c = Classroom.query.filter_by(code=request.form["code"].strip().upper()).first()
    if current_user.role != "student":
        flash("فقط دانش‌آموزان می‌توانند به کلاس بپیوندند.")
    elif not c:
        flash("کلاسی با این کد پیدا نشد.")
    elif current_user not in c.students:
        db.session.add(Enrollment(user_id=current_user.id, class_id=c.id))
        db.session.commit()
        return redirect(url_for("class_view", cid=c.id))
    return redirect(url_for("dashboard"))


@app.route("/class/<int:cid>")
@login_required
def class_view(cid):
    c = get_class(cid)
    ann = Announcement.query.filter_by(class_id=cid).order_by(Announcement.created.desc()).all()
    asg = Assignment.query.filter_by(class_id=cid).order_by(Assignment.due).all()
    mine = {}
    present = absent = 0
    if current_user.role == "student":
        for s in Submission.query.filter_by(student_id=current_user.id).all():
            mine[s.assignment_id] = s
        recs = Attendance.query.filter_by(class_id=cid, student_id=current_user.id).all()
        present = sum(1 for r in recs if r.present)
        absent = len(recs) - present
    return render_template("class.html", c=c, ann=ann, asg=asg, mine=mine,
                           present=present, absent=absent)


@app.route("/class/<int:cid>/announce", methods=["POST"])
@login_required
def announce(cid):
    c = get_class(cid)
    teacher_only(c)
    db.session.add(Announcement(class_id=cid, text=request.form["text"].strip()))
    db.session.commit()
    return redirect(url_for("class_view", cid=cid))


@app.route("/class/<int:cid>/assignment", methods=["POST"])
@login_required
def assignment_new(cid):
    c = get_class(cid)
    teacher_only(c)
    d = request.form.get("due")
    db.session.add(Assignment(
        class_id=cid, title=request.form["title"].strip(),
        description=request.form.get("description", ""),
        due=datetime.strptime(d, "%Y-%m-%d").date() if d else None))
    db.session.commit()
    return redirect(url_for("class_view", cid=cid))


@app.route("/assignment/<int:aid>", methods=["GET", "POST"])
@login_required
def assignment_view(aid):
    a = db.get_or_404(Assignment, aid)
    c = get_class(a.class_id)
    if request.method == "POST":
        if current_user.role == "student":
            s = Submission.query.filter_by(assignment_id=aid, student_id=current_user.id).first()
            if s and s.grade is not None:
                flash("این تکلیف نمره گرفته و دیگر قابل ویرایش نیست.")
            else:
                if not s:
                    s = Submission(assignment_id=aid, student_id=current_user.id)
                    db.session.add(s)
                s.text = request.form["text"].strip()
                s.created = datetime.utcnow()
                db.session.commit()
                flash("پاسخ شما ثبت شد.")
        else:
            teacher_only(c)
            s = db.get_or_404(Submission, int(request.form["sid"]))
            g = request.form.get("grade", "").strip()
            s.grade = float(g) if g else None
            s.feedback = request.form.get("feedback", "")
            db.session.commit()
            flash("نمره ثبت شد.")
        return redirect(url_for("assignment_view", aid=aid))
    subs = Submission.query.filter_by(assignment_id=aid).all()
    mine = next((s for s in subs if s.student_id == current_user.id), None)
    return render_template("assignment.html", a=a, c=c, subs=subs, mine=mine)


@app.route("/class/<int:cid>/attendance", methods=["GET", "POST"])
@login_required
def attendance(cid):
    c = get_class(cid)
    teacher_only(c)
    d = request.values.get("day") or date.today().isoformat()
    day = datetime.strptime(d, "%Y-%m-%d").date()
    if request.method == "POST":
        for s in c.students:
            rec = Attendance.query.filter_by(class_id=cid, student_id=s.id, day=day).first()
            if not rec:
                rec = Attendance(class_id=cid, student_id=s.id, day=day)
                db.session.add(rec)
            rec.present = f"p{s.id}" in request.form
        db.session.commit()
        flash("حضور و غیاب ثبت شد.")
        return redirect(url_for("attendance", cid=cid, day=d))
    recs = {r.student_id: r.present for r in Attendance.query.filter_by(class_id=cid, day=day)}
    return render_template("attendance.html", c=c, day=d, recs=recs)


if __name__ == "__main__":
    app.run(debug=True)
