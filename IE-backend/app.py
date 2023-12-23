from flask import Flask, jsonify, request, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS, cross_origin
from functools import wraps
import uuid # for public id

# for token generation
import jwt
from datetime import datetime, timedelta
from  werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

app.config['CORS_HEADERS'] = 'Content-Type'

app.config['SECRET_KEY'] = 'your secret key'

cors = CORS(app, resources={r'/api/*': {"origins": "*"}})

db = SQLAlchemy(app)

# Database ORMs
class User(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    public_id = db.Column(db.String(50), unique = True)
    username = db.Column(db.String(100))
    password = db.Column(db.String(80))

class URL(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    address = db.Column(db.String(100))
    user_id = db.Column(db.Integer)
    threshold = db.Column(db.Integer)

class Request(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    url_id = db.Column(db.Integer)
    result = db.Column(db.Integer)
    timestamp = db.Column(db.DateTime)

# with app.app_context():
#     db.create_all()
#     db.session.commit()
# add column to Request



# token_required is a decorator function that checks for the presence of a valid JWT in the request header
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # jwt is passed in the request header
        if 'Authorization' in request.headers:
            token = request.headers['Authorization']
        # return 401 if token is not passed
        if not token:
            return jsonify({'message' : 'Token is missing !!'}), 401
  
        try:
            # decoding the payload to fetch the stored details
            # print('****', token)
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            # print('****', data)
            current_user = User.query\
                .filter_by(public_id = data['public_id'])\
                .first()
        except Exception as e:
            print(e)
            return jsonify({
                'message' : 'Token is invalid !!'
            }), 401
        # returns the current logged in users contex to the routes
        return  f(current_user, *args, **kwargs)
  
    return decorated


# sign-up route
@app.route('/signup', methods =['POST'])
def signup():
    # creates a dictionary of the form data
    data = request.form
  
    # gets name, email and password
    username = data.get('username')
    password = data.get('password')
  
    # checking for existing user
    user = User.query\
        .filter_by(username = username)\
        .first()
    if not user:
        # database ORM object
        user = User(
            public_id = str(uuid.uuid4()),
            username = username,
            password = generate_password_hash(password)
        )
        # insert user
        db.session.add(user)
        db.session.commit()
  
        return make_response('Successfully registered.', 201)
    else:
        # returns 202 if user already exists
        return make_response('User already exists. Please Log in.', 202)

# login route
@app.route('/login', methods =['POST'])
def login():
    # creates a dictionary of the form data
    auth = request.form
  
    if not auth or not auth.get('username') or not auth.get('password'):
        # returns 401 if any email or / and password is missing
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm ="Login required !!"'})
    
    user = User.query\
        .filter_by(username = auth.get('username'))\
        .first()
    
    if check_password_hash(user.password, auth.get('password')):
        # print('****', user.public_id)
        token = jwt.encode({
            'public_id' : user.public_id,
            'exp' : datetime.utcnow() + timedelta(minutes = 30)
        }, app.config['SECRET_KEY'])

        return make_response(jsonify({'token' : token,\
                                     'id' : user.id,}), 200)
    
    # returns 403 if password is wrong
    return make_response('Could not verify', 403, {'WWW-Authenticate' : 'Wrong password !!"'})

@app.route('/api/user', methods =['GET'])
@token_required
def test(current_user):
    return jsonify({'message' : 'Hello, ' + current_user.username + ' !!'})

# route to create a new url
@app.route('/api/urls', methods =['POST'])
@token_required
def create_url(current_user):
    data = request.form
    urls = URL.query\
        .filter_by(user_id = current_user.id)\
        .all()
    if len(urls) >= 20:
        return make_response('You have reached the maximum number of urls.', 403)
    address = data.get('address')
    threshold = data.get('threshold')
    url = URL(
        address = address,
        user_id = current_user.id,
        threshold = threshold
    )
    db.session.add(url)
    db.session.commit()
    return make_response('Successfully created.', 201)

# route to get all the urls of the current user
@app.route('/api/urls', methods =['GET']) 
@token_required
def get_urls(current_user):
    urls = URL.query\
        .filter_by(user_id = current_user.id)\
        .all()
    output = []
    for url in urls:
        url_data = {}
        url_data['id'] = url.id
        url_data['address'] = url.address
        url_data['threshold'] = url.threshold
        output.append(url_data)
    
    return jsonify({'urls' : output})

# route to check if the url is up or down
@app.route('/api/urls/<url_id>', methods =['GET'])
@token_required
def get_stat(current_user, url_id):
    url = URL.query\
        .filter_by(id = url_id, user_id = current_user.id)\
        .first()
    if not url:
        return make_response('No url found', 404)
    current_time = datetime.now() - timedelta(hours = 24)
    requests = Request.query\
        .filter_by(url_id = url_id)\
        .all()
    requests = [request for request in requests if request.timestamp > current_time]
    output = []
    for request in requests:
        request_data = {}
        request_data['id'] = request.id
        request_data['result'] = request.result
        output.append(request_data)
    return jsonify({'requests' : output})

# route to delete a url
@app.route('/api/urls/<url_id>', methods =['DELETE'])
@token_required
def delete_url(current_user, url_id):
    url = URL.query\
        .filter_by(id = url_id, user_id = current_user.id)\
        .first()
    if not url:
        return make_response('No url found', 404)
    db.session.delete(url)
    db.session.commit()
    return make_response('Successfully deleted.', 201)

# get url allert which meet the threshold
@app.route('/api/alert', methods =['GET'])
@token_required
def get_alert(current_user):
    urls = URL.query\
        .filter_by(user_id = current_user.id)\
        .all()
    output = []
    for url in urls:
        url_data = {}
        url_data['id'] = url.id
        url_data['address'] = url.address
        url_data['threshold'] = url.threshold
        requests = Request.query\
            .filter_by(url_id = url.id)\
            .all()
        req_res = []
        for request in requests:
            if request.result % 100 != 2:
                req_s = {}
                req_s['id'] = request.id
                req_s['result'] = request.result
                req_res.append(req_s)

        url_data['requests'] = req_res
        if len(req_res) >= url.threshold:
            output.append(url_data)
    print(output)
    return jsonify({'urls' : output})

# dismiss alert
@app.route('/api/alert/<url_id>', methods =['PUT'])
@token_required
def dismiss_alert(current_user, url_id):
    url = URL.query\
        .filter_by(id = url_id, user_id = current_user.id)\
        .first()
    if not url:
        return make_response('No url found', 404)
    requests = Request.query\
        .filter_by(url_id = url_id)\
        .all()
    for request in requests:
        if request.result % 100 != 2:
            db.session.delete(request)
    db.session.commit()
    return make_response('Successfully dismissed.', 201)

# @app.route('/test/database')
# def test_database():
#     for i in range(10):
#         user = User(
#             public_id = str(uuid.uuid4()),
#             username = f"user{i}",
#             password = generate_password_hash(f"password{i}")
#         )
#         print('user', user)
#         db.session.add(user)
#         for j in range(5):
#             url = URL(
#             address = f"http://www.example{j}.com",
#             user_id = user.id,
#             threshold = 3
#             )
#             print(f'url{j}', url)
#         db.session.add(url)
#     db.session.commit()
#     return 'Database created'
    

if __name__ == "__main__":
    # setting debug to True enables hot reload
    # and also provides a debugger shell
    # if you hit an error while running the server
    app.run(debug = True)