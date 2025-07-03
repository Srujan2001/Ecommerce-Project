from flask import Flask,request,render_template,redirect,url_for,flash,session,Response
import mysql.connector
from otp import genotp
from cmail import send_mail
from stoken import entoken,detoken
from flask_session import Session
import bcrypt
import os
import razorpay
import pdfkit
import re
import uuid
client = razorpay.Client(auth=("rzp_test_IVOKUPstFIL8G6","zYUIj2q4pGFSSGwtxPb4PABE"))
application=Flask(__name__)
mydb=mysql.connector.connect(user='root',host='localhost',password='admin',db='ecommerce')
config=pdfkit.configuration(wkhtmltopdf=r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe')
application.secret_key='codegnan2025'
application.config['SESSION_TYPE']='filesystem'
Session(application)



# Only this email is allowed to confirm or reject

AUTHORIZED_EMAIL = 'srujanravuri2001@gmail.com'
pending_admins = {}

@application.route('/admincreate', methods=['GET', 'POST'])
def admincreate():
    if request.method == 'POST':
        username = request.form['username']
        useremail = request.form['email']
        raw_password = request.form['password']
        address = request.form['address']
        agreed = request.form.get('agree')

        try:
            cursor = mydb.cursor(buffered=True)
            cursor.execute('SELECT COUNT(*) FROM admin_details WHERE admin_email=%s', [useremail])
            email_count = cursor.fetchone()[0]
        except Exception as e:
            print(f'Error: {e}')
            flash('Could not fetch data. Please try again.')
            return redirect(url_for('admincreate'))

        if email_count == 0:
            # Hash password using bcrypt
            hashed_password = bcrypt.hashpw(raw_password.encode(), bcrypt.gensalt())

            token = str(uuid.uuid4())
            admindata = {
                'username': username,
                'email': useremail,
                'password': hashed_password,  # Store as bytes for VARBINARY
                'address': address
            }
            pending_admins[token] = admindata

            confirm_url = url_for('admin_confirm', token=token, _external=True)
            reject_url = url_for('admin_reject', token=token, _external=True)

            subject = 'Admin Registration Approval Needed'
            body = f'''
Hello Admin,

A new admin registration request has been submitted.

Name: {username}
Email: {useremail}
Address: {address}

Click to APPROVE: ✅ {confirm_url}
Click to REJECT: ❌ {reject_url}
            '''
            send_mail(to=AUTHORIZED_EMAIL, subject=subject, body=body)
            flash("A confirmation email has been sent to the authorized admin for approval.")
            return redirect(url_for('adminlogin'))
        else:
            flash(f'Email already exists: {useremail}')
            return redirect(url_for('admincreate'))

    return render_template('admincreate.html')


@application.route('/admin_confirm/<token>')
def admin_confirm(token):
    data = pending_admins.pop(token, None)
    if data:
        try:
            cursor = mydb.cursor()
            cursor.execute(
                "INSERT INTO admin_details (admin_username, admin_email, admin_password, address) VALUES (%s, %s, %s, %s)",
                [data['username'], data['email'], data['password'], data['address']]
            )
            mydb.commit()

            # Send approval mail to user
            subject = 'Admin Registration Approved'
            body = f'''
Hi {data['username']},

Your request to become an admin has been approved ✅.

You can now log in using your registered email: {data['email']}.

Thank you and welcome aboard!

Regards,  
Admin Team
            '''
            send_mail(to=data['email'], subject=subject, body=body)

            flash("Admin registered successfully and email sent to the user.")
        except Exception as e:
            flash(f"Failed to save admin: {e}")
    else:
        flash("Invalid or expired confirmation link.")
    return '<p style="color: green; font-weight: bold;font-size: 100px; ">Success</p>'




@application.route('/admin_reject/<token>')
def admin_reject(token):
    data = pending_admins.pop(token, None)
    if data:
        # Send rejection mail to user
        subject = 'Admin Registration Rejected'
        body = f'''
Hi {data['username']},

We regret to inform you that your admin registration request has been ❌ rejected.

If you believe this is a mistake or have any questions, please contact us.

Regards,  
Admin Team
        '''
        send_mail(to=data['email'], subject=subject, body=body)

        flash("Admin registration request has been rejected and user notified.")
    else:
        flash("Invalid or expired rejection link.")
    return redirect(url_for('admincreate'))










@application.route('/')
def home():
    return render_template("welcome.html")

@application.route('/index')
def index():
    try:
        cursor=mydb.cursor(buffered=True)
        cursor.execute('select bin_to_uuid(itemid),item_name,description,item_cost,item_category,item_quantity,created_at,imgname from items')
        items_data=cursor.fetchall()
    except Exception as e:
        print(f'Error is {e}')
        flash('Could not fetch the items')
        return redirect(url_for('index'))
    else:
        return render_template('index.html',items_data=items_data)
    return render_template('index.html')

# @application.route('/admincreate',methods=['GET','POST'])
# def admincreate():
#     if request.method=='POST':
#         username=request.form['username']
#         useremail=request.form['email']
#         password=request.form['password']
#         address=request.form['address']
#         aggred=request.form['agree']
#         print(request.form)

#         try:
#             cursor=mydb.cursor(buffered=True)
#             cursor.execute('select count(admin_email) from admin_details where admin_email=%s',[username])
#             email_count=cursor.fetchone()
#         except Exception as e:
#             print(f'actual error is {e}')
#             flash('Could not fetch data Please try again')
#         else:
#             if email_count[0]==0:
#                 gotp=genotp()
#                 print(gotp)
#                 admindata={'username':username,'useremail':useremail,'password':password,'address':address,'agreed':aggred,'genotp':gotp}
#                 subject='OTP for Admin Verification'
#                 body=f'Use the given otp for admin verify {gotp}'
#                 send_mail(to=useremail,subject=subject,body=body)
#                 flash(f'OTP has been sent given email {useremail}')
#                 return redirect(url_for('otpverify', endata=entoken(admindata)))
#             elif email_count[1]==1:
#                 flash(f'email already existed {username}')
#                 return redirect(url_for('admincreate'))
#     return render_template('admincreate.html')


# @application.route('/otpverify/<endata>',methods=['GET','POST'])
# def otpverify(endata):
#     if request.method=='POST':
#         userotp=request.form['otp']
#         ddata=detoken(data=endata)
#         hashed=bcrypt.hashpw(ddata['password'].encode(),bcrypt.gensalt())
#         print(hashed)
#         if ddata['genotp']==userotp:
#             try:
#                 cursor=mydb.cursor()
#                 cursor.execute('insert into admin_details(admin_username,admin_email,admin_password,address)values(%s,%s,%s,%s)',[ddata['username'],ddata['useremail'],hashed,ddata['address']])
#                 mydb.commit()
#                 cursor.close()
#             except Exception as e:
#                 print(f'the error is {e}')
#                 flash('unable to store data')
#                 return redirect(url_for('admincreate'))
#             else:
#                 flash('Admin Registered Successfully.')
#                 return redirect(url_for('adminlogin'))
#         else:
#             flash(f'OTP wrong')
       
#     return render_template('adminotp.html')


@application.route('/adminlogin',methods=['GET','POST'])
def adminlogin():
    if request.method=='POST':
        try:
            useremail=request.form['email']
            password=request.form['password'].encode()
            cursor=mydb.cursor(buffered=True)
            cursor.execute('select count(admin_email) from admin_details where admin_email=%s',[useremail])
            email_count=cursor.fetchone()
        except Exception as e:
            print(f'the error is {e}')
            flash('Some went wrong Please try again')
            return redirect(url_for('adminlogin'))
        else:
            if email_count[0]==1:
                cursor.execute('select admin_password from admin_details where admin_email=%s',[useremail])
                stored_password=cursor.fetchone()[0]
                print(password,stored_password)
                if bcrypt.checkpw(password,stored_password):
                    session['admin']=useremail
                    print(session)
                    return redirect(url_for('adminpanel'))
                else:
                    flash(f'password wrong')

    return render_template('adminlogin.html')



@application.route('/adminforgot', methods=['GET', 'POST'])
def adminforgot():
    if request.method == 'POST':
        email = request.form['email']
        try:
            cursor = mydb.cursor()
            cursor.execute("SELECT COUNT(*) FROM admin_details WHERE admin_email=%s", [email])
            admin_count = cursor.fetchone()[0]
        except Exception as e:
            print(f"Error: {e}")
            flash("Error connecting to database.")
            return redirect(url_for('adminforgot'))
        
        if admin_count == 1:
            otp = genotp()
            session['admin_reset_otp'] = otp
            session['admin_reset_email'] = email
            send_mail(
                to=email,
                subject="Admin Password Reset OTP",
                body=f"Your OTP to reset your admin password is: {otp}"
            )
            flash(f"An OTP has been sent to {email}")
            return redirect(url_for('admin_verify_reset_otp'))
        else:
            flash("Email not found.")
            return redirect(url_for('adminforgot'))
    return render_template('adminforgotpassword.html')

@application.route('/admin_verify_reset_otp', methods=['GET', 'POST'])
def admin_verify_reset_otp():
    if request.method == 'POST':
        user_otp = request.form['otp']
        if session.get('admin_reset_otp') == user_otp:
            flash("OTP verified. Set new password.")
            return redirect(url_for('admin_newpassword'))
        else:
            flash("Invalid OTP.")
            return redirect(url_for('admin_verify_reset_otp'))
    return render_template("admin_verify_reset_otp.html")

@application.route('/admin_newpassword', methods=['GET', 'POST'])
def admin_newpassword():
    if request.method == 'POST':
        newpass = request.form['password']
        confirmpass = request.form['confirmpassword']

        if newpass != confirmpass:
            flash("Passwords do not match.")
            return redirect(url_for('admin_newpassword'))

        try:
            hashed = bcrypt.hashpw(newpass.encode(), bcrypt.gensalt())
            cursor = mydb.cursor()
            cursor.execute("UPDATE admin_details SET admin_password = %s WHERE admin_email = %s", 
                           [hashed, session['admin_reset_email']])
            mydb.commit()
            cursor.close()

            flash("Password updated successfully. Please login.")
            session.pop('admin_reset_email', None)
            session.pop('admin_reset_otp', None)
            return redirect(url_for('adminlogin'))

        except Exception as e:
            print("Error:", e)
            flash("Failed to update password.")
            return redirect(url_for('admin_newpassword'))

    return render_template("admin_newpassword.html")



@application.route('/adminpanel',methods=['GET','POSt'])
def adminpanel():
    return render_template('adminpanel.html')

@application.route('/additem',methods=['GET','POST'])
def additem():
    if request.method=='POST':
        item_name=request.form['title']
        item_desc=request.form['Discription']
        item_quantity=request.form['quantity']
        item_cost=request.form['price']
        item_category=request.form['category']
        item_image=request.files['file']
        filename=genotp()+'.'+item_image.filename.split('.')[-1]
        print('filename: ',filename)
        try:
            path=os.path.abspath(__file__)
            dname=os.path.dirname(path)
            print(dname)
            static_path=os.path.join(dname,'static')
            print(static_path)
            item_image.save(os.path.join(static_path,filename))
            cursor=mydb.cursor(buffered=True)
            cursor.execute('insert into items(itemid,item_name,description,item_cost,item_quantity,item_category,added_by,imgname) values(uuid_to_bin(uuid()),%s,%s,%s,%s,%s,%s,%s)',[item_name,item_desc,item_cost,item_quantity,item_category,session.get('admin'),filename])
            print('success')
            mydb.commit()
            cursor.close()
        except Exception as e:
            print(f'the error is {e}')
            return redirect(url_for('additem'))
        else:
            flash(f'{item_name[:20]}. add sucessfully')
            return redirect(url_for('adminpanel'))
    return render_template('additem.html')

@application.route('/viewitems')
def viewitems():
    if session.get('admin'):
        try:
            cursor=mydb.cursor(buffered=True)
            cursor.execute('select bin_to_uuid(itemid),item_name,item_cost,imgname,description from items where added_by=%s',[session.get('admin')])
            itemsdata=cursor.fetchall()
        except Exception as e:
            print(f'the error is {e}')
            flash('Could not fetch the data')
            return redirect(url_for('admindashboard'))
        else:
            return render_template('viewall_items.html',itemsdata=itemsdata)
    else:
        flash(f'Please login first')
        return redirect(url_for('adminlogin'))

@application.route('/view_item/<itemid>')
def view_item(itemid):
    try:
        cursor=mydb.cursor(buffered=True)
        cursor.execute('select bin_to_uuid(itemid),item_name,description,item_cost,item_quantity,item_category,created_at,imgname from items where itemid=uuid_to_bin(%s) and added_by=%s',[itemid,session.get('admin')])
        itemdata=cursor.fetchone()
    except Exception as e:
        print(f'ERROR IS: {e}')
        flash("Couldn't fetch the data")
        return redirect(url_for('viewitems'))
    else:
        return render_template('view_item.html',itemdata=itemdata)
    return render_template('view_item.html')

@application.route('/updateitem/<itemid>',methods=['GET','POST'])
def updateitem(itemid):
    try:
        cursor=mydb.cursor(buffered=True)
        cursor.execute('select bin_to_uuid(itemid),item_name,description,item_cost,item_quantity,item_category,created_at,imgname from items where itemid=uuid_to_bin(%s) and added_by=%s',[itemid,session.get('admin')])
        itemdata=cursor.fetchone()
    except Exception as e:
        print(f'ERROR IS: {e}')
        flash("Couldn't fetch the data")
        return redirect(url_for('viewitems'))
    else:
        if request.method=='POST':
            item_name=request.form['title']
            item_desc=request.form['Description']
            item_price=request.form['price']
            item_category=request.form['category']
            print(item_category)
            item_quantity=request.form['quantity']
            item_image=request.files['file']
            if item_image.filename=='':
                filename=itemdata[7]
            else:
                filename=genotp()+'.'+item_image.filename.split('.')[-1]
                path=os.path.abspath(__file__)
                dname=os.path.dirname(path)
                print(dname)
                static_path=os.path.join(dname,'static')
                print(static_path)
                item_image.save(os.path.join(static_path,filename))
            cursor=mydb.cursor(buffered=True)
            cursor.execute('update items set item_name=%s,description=%s,item_cost=%s,item_quantity=%s,item_category=%s,imgname=%s where itemid=uuid_to_bin(%s) and added_by=%s',[item_name,item_desc,item_price,item_quantity,item_category,filename,itemid,session.get('admin')])
            mydb.commit()
            cursor.close()
            flash('item updated')
            return redirect(url_for('view_item',itemid=itemid))
        return render_template('update_item.html',item_data=itemdata)

@application.route('/deleteitem/<itemid>')
def deleteitem(itemid):
    try:
        cursor=mydb.cursor(buffered=True)
        cursor.execute('select imgname from items where itemid=uuid_to_bin(%s) and added_by=%s',[itemid,session.get('admin')])
        stored_imgname=cursor.fetchone()[0]
        path=os.path.abspath(__file__)
        dname=os.path.dirname(path)
        static_path=os.path.join(dname,'static')
        os.remove(os.path.join(static_path,stored_imgname))
        cursor.execute('delete from items where itemid=uuid_to_bin(%s) and added_by=%s',[itemid,session.get('admin')])
        mydb.commit()
        cursor.close()
    except Exception as e:
        print(e)
        flash(f'Item could not delete')
        return redirect(url_for('viewitems'))
    else:
        flash(f'{itemid} deleted successfully')
        return redirect(url_for('adminpanel'))


@application.route('/adminlogout')
def adminlogout():
    if session.get('admin'):
        session.pop('admin')
        return redirect(url_for('index'))
    else:
        flash('To Logout pls login first')
        return redirect(url_for('adminlogin'))



@application.route('/usersignup',methods=['GET','POST'])
def usersignup():
    if request.method=='POST':
        uname=request.form['username']
        uemail=request.form['email']
        uaddress=request.form['address']
        upassword=request.form['password']
        ugender=request.form['usergender']
        try:
            cursor=mydb.cursor()
            cursor.execute('select count(useremail) from users where useremail=%s',[uemail])
            user_email_count=cursor.fetchone()
        except Exception as e:
            print(f'actual erorr is {e}')
            flash('Could not reach the data pls try again')
            return redirect(url_for('usersignup'))
        else:
            if user_email_count[0]==0:
                uotp=genotp()
                userdata={'username':uname,'useremail':uemail,'password':upassword,'address':uaddress,'gender':ugender,'otp':uotp}
                subject='OTP for User Verification'
                body=f'Use the given otp for user verify {uotp}'
                send_mail(to=uemail,subject=subject,body=body)
                flash(f'OTP has been sent to the registered email{uemail}')
                return redirect(url_for('user_otpverify',endata=entoken(data=userdata)))
            elif user_email_count[0]==1:
                flash(f'Email already existed {uemail}')
                return redirect(url_for('usersignup'))
    return render_template('usersignup.html')





@application.route('/user_otpverify/<endata>',methods=['GET','POST'])
def user_otpverify(endata):
    if request.method=='POST':
        userotp=request.form['otp']
        ddata=detoken(data=endata)
        hashed=bcrypt.hashpw(ddata['password'].encode(),bcrypt.gensalt())
        print(hashed)
        if ddata['otp']==userotp:
            try:
                cursor=mydb.cursor()
                cursor.execute('insert into users(username,useremail,password,address) values (%s,%s,%s,%s)',[ddata['username'],ddata['useremail'],hashed,ddata['address']])
                mydb.commit()
                cursor.close()
            except Exception as e:
                print(f'the error is {e}')
                flash('unable to store data')
                return redirect(url_for('usersignup'))
            else:
                flash('Admin Registered Successfully.')
                return redirect(url_for('userlogin'))
        else:
            flash(f'OTP wrong')
       
    return render_template('userotp.html')





@application.route('/userlogin',methods=['GET','POST'])
def userlogin():
    if request.method=='POST':
        try:
            uemail=request.form['email']
            password=request.form['password'].encode()
            cursor=mydb.cursor(buffered=True)
            cursor.execute('select count(useremail) from users where useremail=%s',[uemail])
            user_email_count=cursor.fetchone()
        except Exception as e:
            print(e)
            flash('Something went wrong')
            return redirect(url_for('userlogin'))
        else:
            if user_email_count[0]==1:
                cursor.execute('select password from users where useremail=%s',[uemail])
                user_stored_password=cursor.fetchone()[0]
                print(password,user_stored_password.decode())
                if bcrypt.checkpw(password,user_stored_password):
                    session['user']=uemail
                    if not session.get(uemail):
                        session[uemail]={}
                        session.modify=True
                    print(session)   
                    return redirect(url_for('index'))
                else:
                    flash(f'password wrong')
                    return redirect(url_for('userlogin'))
            elif user_email_count[0]==0:
                flash(f'{uemail} not found')
                return redirect(url_for('userlogin'))
    return render_template('userlogin.html')
    

@application.route('/forgotpassword', methods=['GET', 'POST'])
def forgotpassword():
    if request.method == 'POST':
        email = request.form['email']
        try:
            cursor = mydb.cursor()
            cursor.execute("SELECT COUNT(*) FROM users WHERE useremail=%s", [email])
            user_count = cursor.fetchone()[0]
        except Exception as e:
            print(f"Error: {e}")
            flash("Error connecting to database.")
            return redirect(url_for('forgotpassword'))
        
        if user_count == 1:
            otp = genotp()
            session['reset_otp'] = otp
            session['reset_email'] = email
            send_mail(
                to=email,
                subject="Password Reset OTP",
                body=f"Your OTP to reset password is: {otp}"
            )
            flash(f"An OTP has been sent to {email}")
            return redirect(url_for('verify_reset_otp'))
        else:
            flash("Email not found.")
            return redirect(url_for('forgotpassword'))
    return render_template('userforgotpassword.html')

@application.route('/verify_reset_otp', methods=['GET', 'POST'])
def verify_reset_otp():
    if request.method == 'POST':
        user_otp = request.form['otp']
        if session.get('reset_otp') == user_otp:
            flash("OTP verified. Set new password.")
            return redirect(url_for('newpassword'))
        else:
            flash("Invalid OTP.")
            return redirect(url_for('verify_reset_otp'))
    return render_template("user_verify_reset_otp.html")

@application.route('/newpassword', methods=['GET', 'POST'])
def newpassword():
    if request.method == 'POST':
        newpass = request.form['password']
        confirmpass = request.form['confirmpassword']

        if newpass != confirmpass:
            flash("Passwords do not match.")
            return redirect(url_for('newpassword'))

        try:
            hashed = bcrypt.hashpw(newpass.encode(), bcrypt.gensalt())
            cursor = mydb.cursor()
            cursor.execute("UPDATE users SET password = %s WHERE useremail = %s", [hashed, session['reset_email']])
            mydb.commit()
            cursor.close()

            flash("Password updated successfully. Please login.")
            session.pop('reset_email', None)
            session.pop('reset_otp', None)
            return redirect(url_for('userlogin'))

        except Exception as e:
            print("Error:", e)
            flash("Failed to update password.")
            return redirect(url_for('newpassword'))

    return render_template("usernewpassword.html")



@application.route('/userlogout')
def userlogout():
    if session.get('user'):
        session.pop('user')
        session.modify=True
        return redirect(url_for('index'))
    else:
        return redirect(url_for('userlogin'))

@application.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')



@application.route('/category,<ctype>')
def category(ctype):
    try:
        cursor=mydb.cursor(buffered=True)
        cursor.execute('select bin_to_uuid(itemid),item_name,description,item_cost,item_quantity,item_category,created_at,imgname from items where item_category=%s',[ctype])
        items_data=cursor.fetchall()
    except Exception as e:
        print(f'Error is : {e}')
        flash('Could not fetch the items')
        return redirect(url_for('index'))
    return render_template('dashboard.html',items_data=items_data)

@application.route('/addcart/<itemid>/<name>/<price>/<category>/<img>')
def addcart(itemid,name,price,category,img):
    if session.get('user'):
        if itemid not in session[session.get('user')]:
            session[session.get('user')][itemid] = [name,price,1,img,category]
            session.modify=True
            flash(f'{name[0:10]} item added to cart')
            return redirect(url_for('index'))
        else:
            session[session.get('user')][itemid][2]+=1
            flash(f'item already in cart')
            return redirect(url_for('index'))
    else:
        return redirect(url_for('userlogin'))


@application.route('/viewcart')
def viewcart():
    if session.get('user'):
        items=session[session.get('user')]
        print(items)
        if items:
            return render_template('cart.html',items=items)
        else:
            flash('No items in cart')
            return redirect(url_for('index'))
    else:
        flash('Pls login first')
        return redirect(url_for('userlogin'))


@application.route('/removecart/<itemid>')
def removecart(itemid):
    if session.get('user'):
        if session[session.get('user')]:
            session[session.get('user')].pop(itemid)
            session.modify=True
            flash(f'{itemid}item removed from cart')
            return redirect(url_for('viewcart'))
        else:
            flash('No items in cart')
    else:
        flash('Please login first')
        return redirect(url_for('userlogin'))





@application.route('/pay/<itemid>/<name>/<float:price>/<quantity>',methods=['GET','POST'])
def pay(itemid,name,price,quantity):
    if session.get('user'):
        try:
            if request.method=='POST':
                qyt=int(request.form['qyt'])
            
        except Exception as e:
            print(f'Error is : {e}')
            flash('Could not fetch the payment')
            return redirect(url_for('viewcart'))
        else:
                qyt=int(quantity)
                price=price*100
                amount=price*qyt
                print(amount,qyt)
                print(f'creating payment for item:{itemid}, name :{name},price:{amount}')
                order=client.order.create({
                    "amount":amount,
                    "currency":"INR",
                    "payment_capture":'1'})
                print(f'order created :{order}')
                return render_template('pay.html',order=order,itemid=itemid,name=name,total_amount=amount)
    else:
        flash('pls login')
        return redirect(url_for('userlogin'))


@application.route('/success', methods=['GET', 'POST'])
def success():
    if request.method == 'POST':
        payment_id = request.form['razorpay_payment_id']
        order_id = request.form['razorpay_order_id']
        order_signature = request.form['razorpay_signature']
        itemid = request.form['itemid']
        name = request.form['name']
        total_amount = float(request.form['total_price'])

        params_dict = {
            'razorpay_payment_id': payment_id,
            'razorpay_order_id': order_id,
            'razorpay_signature': order_signature
        }

        try:
            client.utility.verify_payment_signature(params_dict)
        except razorpay.errors.SignatureVerificationError:
            return 'Payment verification failed!', 400
        else:
            cursor = mydb.cursor(buffered=True)
            cursor.execute('INSERT INTO orders (item_id, item_name, total, payment_by) VALUES (UUID_TO_BIN(%s), %s, %s, %s)',[itemid, name, total_amount/100, session.get('user')])
            mydb.commit()
            flash(f'order will be placed succesfully {total_amount}')
            return redirect(url_for('index'))

@application.route('/orders')
def orders():
    cursor=mydb.cursor()
    cursor.execute('select order_id,bin_to_uuid(item_id),item_name,total,payment_by from orders where payment_by=%s',[session.get('user')])
    data=cursor.fetchall()
    return render_template('orders.html',user_orders=data)


@application.route('/description/<itemid>')
def description(itemid):
    try:
        cursor=mydb.cursor(buffered=True)
        cursor.execute('select bin_to_uuid(itemid),item_name,description,item_cost,item_quantity,item_category,imgname,created_at from items where itemid=uuid_to_bin(%s)',[itemid])
        itemdata=cursor.fetchone()
    except Exception as e:
        print(f'ERROR:{e}')
        flash('could not fetch deatails')
        return redirect(url_for('index'))
    else:
        return render_template('description.html',item_data=itemdata)

@application.route('/addreview/<itemid>',methods=['GET','POST'])
def addreview(itemid):
    if request.method=='POST':
        description=request.form['review']
        rate=request.form['rate']
        try:
            cursor=mydb.cursor()
            cursor.execute('insert into reviews(review_text,itemid,added_by,rating) values(%s,uuid_to_bin(%s),%s,%s)',[description,itemid,session.get('user'),rate])
            mydb.commit()
        except Exception as e:
            print(f'Error is {e}')
            flash('could not add review')
            return redirect(url_for('addreview',itemid=itemid))
        else:
            flash('Review added successfully')
            return redirect(url_for('description',itemid=itemid))
    return render_template('review.html')



@application.route('/readreview/<itemid>')
def readreview(itemid):
    try:
        cursor=mydb.cursor(buffered=True)
        cursor.execute('select bin_to_uuid(itemid),item_name,description,item_cost,item_quantity,item_category,imgname,created_at from items where itemid=uuid_to_bin(%s)',[itemid])
        itemdata=cursor.fetchone()
        cursor.execute('select * from reviews where itemid=uuid_to_bin(%s)',[itemid])
        reviewdata=cursor.fetchall()
        print('reviewdata :',reviewdata)
    except Exception as e:
            print(f'Error is {e}')
            flash('could not add review')
            return redirect(url_for('description',itemid=itemid))
    else:
        return render_template('readreview.html',reviewdata=reviewdata,item_data=itemdata)


@application.route('/getinvoice/<ordid>.pdf')
def getinvoice(ordid):
    if session.get('user'):
        try:
            cursor=mydb.cursor(buffered=True)
            cursor.execute('select * from orders where order_id=%s and payment_by=%s',[ordid,session.get('user')])
            order_data=cursor.fetchone()
            cursor.execute('select useremail,username,address,gender from users where useremail=%s',[session.get('user')])
            user_data=cursor.fetchone()
            html=render_template('bill.html',order_data=order_data,user_data=user_data)
            pdf=pdfkit.from_string(html,False,configuration=config)
            response=Response(pdf,content_type='applicationlication/pdf')
            response.headers['content-Disposition']='inline;filename=output.pdf'
            return response
        except Exception as e:
            print(f'error:{e}')
            flash('could not convert pdf')
            return redirect(url_for('orders'))
    
    else:
        flash('pls login')
        return redirect(url_for('userlogin'))


@application.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('title')
        email = request.form.get('email')
        description = request.form.get('description')

        try:
            cursor = mydb.cursor(buffered=True)
            cursor.execute("INSERT INTO contact_details (name, email, message) VALUES (%s, %s, %s)", (name, email, description))
            mydb.commit()  # <-- corrected here
            flash("Your message has been submitted successfully!", "success")
        except Exception as e:
            flash(f"Error: {e}", "danger")
            
        return redirect(url_for('index'))
    
    return render_template('contact.html')


@application.route('/search', methods=['GET', 'POST'])
def search():
    if request.method == 'POST':
        sdata = request.form['search'].strip()
        pattern = re.compile(r'^[A-Za-z0-9 ]+$', re.IGNORECASE)

        if pattern.match(sdata):  # checks if valid alphanumeric
            try:
                cursor = mydb.cursor(buffered=True)
                query = '''
                    SELECT BIN_TO_UUID(itemid), item_name, description, item_cost, item_quantity,
                           item_category, created_at, imgname
                    FROM items
                    WHERE itemid LIKE %s OR item_name LIKE %s OR description LIKE %s
                          OR item_cost LIKE %s OR item_category LIKE %s OR created_at LIKE %s
                '''
                values = tuple('%' + sdata + '%' for _ in range(6))
                cursor.execute(query, values)
                items_data = cursor.fetchall()
                cursor.close()

                if not items_data:
                    flash('No matching items found.')
                    return redirect(url_for('index'))

                return render_template('dashboard.html', items_data=items_data)
            except Exception as e:
                print(f'Error is {e}')
                flash('Could not fetch search data')
                return redirect(url_for('index'))
        else:
            flash('Invalid search input. Please enter letters or numbers only.')
            return redirect(url_for('index'))









application.run(use_reloader=True,debug=True)
