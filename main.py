from flask import Flask, request,render_template, g, redirect, url_for, session, escape
import sqlite3, hashlib
from werkzeug import secure_filename
import os

DATABASE = './db/web.db'
app = Flask(__name__)
app.secret_key='abcdefg'
UPLOAD_FOLDER= './upload/'
ALLOWED_EXTENSIONS = set(['txt','pdf','png','jpg','jpeg','gif','hwp'])
def init_db():
	with app.app_context():
		db = get_db()
		print db
		with app.open_resource('schema.sql', mode='r') as f:
		    db.cursor().executescript(f.read())
		db.commit()

def get_db():
	db = getattr(g,'_database',None)
	if db is None:
		db = g._daatbase = sqlite3.connect(DATABASE)
		db .row_factory = sqlite3.Row
	return db

def login_check(user_id, user_pw):
        hash_pw = hashlib.sha224(user_pw).hexdigest()
        query = "select * from users where user_id ='%s' AND user_pw = '%s'" %(user_id,hash_pw)
        db = get_db()
        rv = db.execute(query)
        res = rv.fetchall()
        rv.close()
        return res

def reg_user(user_id, user_pw, user_name, user_pnum):
        hash_pw = hashlib.sha224(user_pw).hexdigest()
        query = "insert into users (user_id,user_pw, user_name, user_pnum) values ('%s','%s','%s','%s')" %(user_id,hash_pw, user_name, user_pnum)
        db = get_db()
        db.execute(query)
        res = db.commit()
        return res

def show_board():
    query = "select idx, b_name,b_writer, datetime from board"
    db = get_db()
    rv = db.execute(query)
    res = rv.fetchall()
    rv.close()
    print res
    return res

def insert_board(r_name,r_writer,r_data,r_file,r_path):
    query = "insert into board (b_name,b_writer,datetime,b_data,b_file,b_fpath) values ('%s','%s',DATETIME('now'),'%s','%s','%s')" % (r_name,r_writer,r_data,r_file,r_path)
    db = get_db()
    db.execute(query)
    res = db.commit()
    print res
    return res

def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.',1)[1].lower() in ALLOWED_EXTENSIONS

def secession_user(user_id):
    query = "delete from users where user_id= '%s' " %(user_id)
    db = get_db()
    db.execute(query)
    res = db.commit()
    print res
    return res

def edituser(user_pw,user_name,user_pnum,user_id):
    hash_pw = hashlib.sha224(user_pw).hexdigest()
    query = "update users SET user_pw = '%s', user_name = '%s', user_pnum = '%s'  where user_id = '%s'" % (hash_pw, user_name,user_pnum,user_id)
    db = get_db()
    db.execute(query)
    res = db.commit()
    print res
    return res

def show_board_view(idx):
    query = "select b_name, b_writer, b_data, datetime, b_file, idx from board where idx= '%s'" %(idx)
    db = get_db()
    rv = db.execute(query)
    res = rv.fetchall()
    rv.close()
    print res
    return res

def update_board(eb_idx,eb_data,eb_file,f_path):
    query = "update board SET b_data='%s',b_file='%s',b_fpath='%s' where idx = '%s'" %(eb_data,eb_file,f_path,eb_idx)
    db = get_db()
    db.execute(query)
    res = db.commit()
    print res
    return res

def delete_board_list(b_idx):
    query = "delete from board where idx='%s'" %(b_idx)
    db = get_db()
    db.execute(query)
    res = db.commit()
    print res
    return res

def show_board_comment(idx):
    query = "select * from bcomment where board_idx = '%s'" %(idx)
    db = get_db()
    rv = db.execute(query)
    res = rv.fetchall()
    rv.close()
    print "--------------------------------------------------------"
    print res
    return res

def show_comment(idx):
    query = "select * from bcomment where com_idx = '%s'" %(idx)
    db = get_db()
    rv = db.execute(query)
    res = rv.fetchall()
    rv.close()
    print "show comment"
    print res
    return res

def insert_board_comment(board_idx,c_writer,c_data):
    query = "insert into bcomment (board_idx,c_writer,c_data,datetime) values ('%s','%s','%s',DATETIME('now'))" %(board_idx,c_writer,c_data)
    db =get_db()
    rv = db.execute(query)
    res = db.commit()
    print res
    return res

def edit_board_comment(c_data,c_idx):
    query = "update bcomment SET c_data = '%s' where com_idx = '%s' " %(c_data,c_idx)
    db = get_db()
    rv = db.execute(query)
    res = db.commit()
    print res
    return res

def delete_board_comment(c_idx):
    query = "delete from bcomment where com_idx='%s'" %(c_idx)
    db = get_db()
    db.execute(query)
    res = db.commit()
    print res
    return res
def comment_id(idx):
    query = "select c_writer from bcomment where com_idx='%s'"%(idx)
    db = get_db()
    rv = db.execute(query)
    res = rv.fetchall()
    rv.close()
    return res

def board_id(idx):
    query = "select b_name from board where idx='%s'"%(idx)
    db = get_db()
    rv = db.execute(query)
    res = rv.fetchall()
    rv.close()
    return res

@app.route('/',methods=['GET','POST'])
def index():
	if request.method == 'GET':
            if 'user_id' in session:
                res = "Hello %s Welcome" % (escape(session['user_id']))
                return render_template('index.html',name = res)
            else:
                return render_template('login.html')
        else:
            return redirect(url_for('index'))

@app.route('/secession', methods=['GET','POST'])
def secession():
    if 'user_id' in session:
        res = "%s" % (escape(session['user_id']))
        suid = session['user_id']
        secession_user(suid)
        return redirect(url_for('logout'))
    else :
        return render_template('login.html')
    return ''

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method == 'GET':
        if 'user_id' in session:
            return redirect(url_for('index'))
        else :
            return  render_template('login.html')
    else :
        uid = request.form.get('user_id')
        upw = request.form.get('user_pw')
        check = login_check(uid,upw)
        if check:
            session['user_id'] = uid
        return redirect(url_for('login'))
    return ''

@app.route('/reg', methods=["GET","POST"])
def reg():
    if request.method == 'GET':
        if 'user_id' in session:
            return redirect(url_for('index'))
        else:
            return render_template('reg.html')
    else:
        if 'user_id' in session:
            return redirect(url_for('login'))
        else:
            uid = request.form.get('user_id')
            upw = request.form.get('user_pw')
            uname = request.form.get('user_name')
            upnum = request.form.get('user_pnum')
            reg_user(uid,upw,uname,upnum)
            session['user_id'] = uid
            return redirect(url_for('index'))
        return redirect(url_for('login'))
    return ''

@app.route('/user_edit', methods=['GET','POST'])
def edit_user():
    if request.method == 'GET':
        if 'user_id' in session:
            res = escape(session['user_id'])
            return render_template('edituser.html',boarddata = res)
        else:
            return render_template('login.html')
    else :
        if 'user_id' in session:
            upw = request.form.get('user_pw')
            uname = request.form.get('user_name')
            upnum = request.form.get('user_pnum')
            uid = escape(session['user_id'])
            edituser(upw,uname,upnum,uid)
            return redirect(url_for('logout'))
        else :
            return redirect(url_for('login'))
    return ''


@app.route('/logout')
def logout():
    session.pop('user_id',None)
    return redirect(url_for('login'))

@app.route('/board')
def show_board_list():
    if 'user_id' in session:
        res = show_board()
        return render_template('board.html',boarddata = res)
    else :
        return redirect(url_for('login'))
    return ''

@app.route('/write_board',methods=["GET","POST"])
def write_board():
    if request.method == 'GET':
        if 'user_id' in session:
            res = escape(session['user_id'])
            return render_template('write_board.html',boarddata=res)
        else :
            return render_template('login.html')
    elif request.method == 'POST':
        r_name = request.form.get('board_title')
        r_data = request.form.get('board_data')
        if 'board_file' in request.files:
            r_file = request.files['board_file']
            if allowed_file(r_file.filename):
                f_name = secure_filename(r_file.filename)
                f_path = './upload/' + f_name + "." + f_name.rsplit('.')[1]
                r_file.save(f_path)
        else:
            f_name = ''
            f_path = ''
        res = insert_board(escape(session['user_id']),r_name,r_data,f_name,f_path)
        return redirect(url_for('show_board_list'))
    return ''

@app.route('/board/<idx>', methods=['GET','POST'])
def board_view(idx):
    if request.method == 'GET':
        if 'user_id' in session:
            res = show_board_view(idx)
            if res[0]['b_writer'] == escape(session['user_id']):
                l_check = 'true'
            else:
                l_check = 'false'
            c_data = show_board_comment(idx)
            c_id = escape(session['user_id'])
            return render_template('boardview.html',user_id = c_id, boarddata=res,check = l_check,c_data = c_data, writer = escape(session['user_id']))
        else:
            return redirect(url_for('login'))
        return ''
    return ''

@app.route('/edit_board/<idx>',methods=['GET','POST'])
def edit_board(idx):
    if request.method == 'GET':
        if 'user_id' in session:
            res = show_board_view(idx)
            return render_template('editboard.html',boarddata = res)
        else :
            return redirect(url_for('/login'))
    else:
        eb_idx = request.form.get('b_idx')
        eb_name = request.form.get('b_name')
        eb_data = request.form.get('b_data')
        eb_id = request.form.get('user_id')
        if 'board_file' in request.files:
            eb_file = request.files['board_file']
            if allowed_file(eb_file.filename):
                f_name = secure_filename(eb_file.filename)
                f_path = './upload/' + f_name + "." + f_name.rsplit('.')[1]
                r_file.save(f_path)
        else:
            f_name = ''
            f_path = ''
        if session['user_id']==eb_id:
            res = update_board(eb_idx,eb_data,f_name,f_path)
        else :
            return "Access Denied"
        return redirect(url_for('show_board_list'))
    return ''

@app.route('/delete_board/<idx>', methods=['GET','POST'])
def delete_board(idx):
    if request.method == 'GET':
        if 'user_id' in session:
            b_id = board_id(idx)
            if session['user_id']==b_id:
                res = delete_board_list(idx)
                return redirect(url_for('show_board_list'))
            else:
                return "Access Denied"
        else:
            return redirect(url_for('/login'))
    return ''


@app.route('/edit_comment/<com_idx>', methods=['GET','POST'])
def edit_comment(com_idx):
    if request.method == 'GET':
        if 'user_id' in session:
            res = show_comment(com_idx)
            return render_template('editcomment.html',commentdata = res)
        else :
            return redirect(url_for('/login'))
    else:
        if 'user_id' in session:
            c_idx = request.form.get('c_idx')
            b_idx = request.form.get('b_idx')
            c_data = request.form.get('com_data')
            if session['user_id'] == request.form.get('user_id'):
                upres = edit_board_comment(c_data,c_idx)
                return redirect(url_for('show_board_list'))
            else :
                return 'Access Denied'
        else:
            return redirect(url_for('/login'))
    return ''

@app.route('/delete_comment/<com_idx>', methods=['GET','POST'])
def delete_comment(com_idx):
    if request.method == 'GET':
        if 'user_id' in session:
            get_id = comment_id(com_idx)
            if session['user_id'] == get_id:
                res = delete_board_comment(com_idx)
                return redirect(url_for('show_board_list'))
            else:
                return 'Access Dineid'
        else:
            return redirect(url_for('/login'))
    return ''

@app.route('/write_comment', methods=['GET','POST'])
def write_comment():
    if request.method == 'POST':
        if 'user_id' in session:
            c_data = request.form.get('comment')
            b_idx = request.form.get('b_idx')
            res = insert_board_comment(b_idx,escape(session['user_id']),c_data)
            return redirect(url_for('show_board_list'))
        else:
            return redirect(url_for('/'))
    return ''


if __name__ == '__main__' :
	#init_db()
	app.run(debug=True, port=8888, host='0.0.0.0')
