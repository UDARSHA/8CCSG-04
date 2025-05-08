from flask import Flask, render_template, request, flash, redirect,jsonify
from datetime import datetime
import sqlite3
import numpy as np
import telepot
from flask import render_template, request, make_response
# from xhtml2pdf import pisa  # For PDF generation
import io

import joblib
multi_class_model = joblib.load('anomaly_model.pkl') 


# Initialize Telegram bot
bot = telepot.Bot("7667861542:AAHrDtUs4e8C2KKtIcLMwpeIdYiwtuoqqiU")
CHAT_ID = "1648981627"




# Label mapping
label_mapping = {
    0: "Normal",
    1: "DDos",
    2: "PROBE",
    3: "U 2 R",
    4: "R 2 L"
}


app = Flask(__name__)

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/send_alert', methods=['POST'])
def send_alert():
    try:
        data = request.get_json()
        attack_type = data.get('attack_type', 'Unknown Attack')
        
        # Create alert message
        message = f"""🚨 *SECURITY ALERT* 🚨
        
*Attack Type:* {attack_type}
*Timestamp:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        
*Recommended Actions:*
- Isolate affected systems
- Preserve logs for analysis
- Initiate incident response protocol"""

        # Send to Telegram
        bot.sendMessage(CHAT_ID, message, parse_mode='Markdown')
        
        return jsonify({
            'success': True,
            'message': 'Alert successfully sent to security team!'
        })
        
    except Exception as e:
        print(f"\n\n\n ERROR !!! \n\n\n {e} \n\n\n")
        return jsonify({
            'success': False,
            'message': f'Failed to send alert: {str(e)}'
        }), 500


@app.route('/index')
def index():
    return render_template('index.html')


@app.route('/aboutus')
def aboutus():
    return render_template('developers_page.html')


@app.route('/userlog', methods=['GET', 'POST'])
def userlog():
    if request.method == 'POST':

        connection = sqlite3.connect('user_data.db')
        cursor = connection.cursor()

        name = request.form['name']
        password = request.form['password']

        query = "SELECT name, password FROM user WHERE name = '"+name+"' AND password= '"+password+"'"
        cursor.execute(query)

        result = cursor.fetchall()

        if len(result) == 0:
            return render_template('index.html', msg='Sorry , Incorrect Credentials Provided,  Try Again')
        else:
            return render_template('logged.html')

    return render_template('index.html')


@app.route('/userreg', methods=['GET', 'POST'])
def userreg():
    if request.method == 'POST':

        connection = sqlite3.connect('user_data.db')
        cursor = connection.cursor()

        name = request.form['name']
        password = request.form['password']
        mobile = request.form['phone']
        email = request.form['email']
        
        print(name, mobile, email, password)

        command = """CREATE TABLE IF NOT EXISTS user(name TEXT, password TEXT, mobile TEXT, email TEXT)"""
        cursor.execute(command)

        cursor.execute("INSERT INTO user VALUES ('"+name+"', '"+password+"', '"+mobile+"', '"+email+"')")
        connection.commit()

        return render_template('index.html', msg='Successfully Registered')
    
    return render_template('index.html')

@app.route('/logout')
def logout():
    return render_template('index.html')

@app.route('/alert')
def alert():
    return render_template('index.html')


@app.route("/kidneyPage")
def kidneyPage():
    return render_template('logged.html')
    


@app.route("/predictPage", methods = ['POST', 'GET'])
def predictPage():
    if request.method == 'POST':
        attack_neptune = float(request.form['attack_neptune'])
        attack_normal = float(request.form['attack_normal'])
        attack_satan = float(request.form['attack_satan'])
        count = float(request.form['count'])
        dst_host_diff_srv_rate = float(request.form['dst_host_diff_srv_rate'])
        dst_host_same_src_port_rate = float(request.form['dst_host_same_src_port_rate'])
        dst_host_same_srv_rate = float(request.form['dst_host_same_srv_rate'])
        dst_host_srv_count = float(request.form['dst_host_srv_count'])
        flag_S0 = float(request.form['flag_S0'])
        flag_SF = float(request.form['flag_SF'])
        last_flag = float(request.form['last_flag'])
        logged_in = float(request.form['logged_in'])
        same_srv_rate = float(request.form['same_srv_rate'])
        serror_rate = float(request.form['serror_rate'])
        service_http = float(request.form['service_http'])

        # Convert inputs into an array
        features = np.array([[attack_neptune, attack_normal, attack_satan, count,
                            dst_host_diff_srv_rate, dst_host_same_src_port_rate, dst_host_same_srv_rate,
                            dst_host_srv_count, flag_S0, flag_SF, last_flag, logged_in,
                            same_srv_rate, serror_rate, service_http]])

        # Make prediction using the model
        predicted_class = multi_class_model.predict(features)[0]
        # Step 4: Output the result
        print(f"The data point is classified as class: \n\n\n{predicted_class} \n\n\n")

        # Label mapping
        classes = ["Normal","DDos","PROBE","U 2 R", "R 2 L"]
        predicted_class=int(predicted_class)

        # Map the predicted class to its label
        predicted_label = classes[predicted_class]

        if predicted_label != "Normal":
            return render_template('predict.html', out=predicted_class ,pred=f"Alert! Attack Should be {predicted_label}")
        else:
            return render_template('predict.html', out=predicted_class ,pred=f"Safe ! pattern is Normal ") 
    
    return render_template('logged.html')

if __name__ == '__main__':
	app.run(debug = True, use_reloader=False)
