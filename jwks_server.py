from flask import Flask, request, jsonify
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import jwt
import base64

#initialize flask app for web server
app = Flask(__name__)

#dictionary to store keys and their expiry time
keys = {}

def generate_rsa_key(expired=False):
    #generates the RSA key pair
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    #kid is incremented by one for every generated pair
    key_id = str(len(keys) + 1)
    #if the keys are expired then the expiry time is set to 1 minute in the past so it cannot be valid
    if expired:
        expiration_time = datetime.utcnow() - timedelta(minutes=1)
    else:
        expiration_time = datetime.utcnow() + timedelta(minutes=5)
    #key pair is saved to the dictionary
    keys[key_id] = (public_key, private_key, expiration_time, expired)
    return key_id
    
def base64_encode(number):
    #converts n (public key mmodulus) into base64 encoded string value
    byte_length = (number.bit_length() + 7) // 8
    byte_array = number.to_bytes(byte_length, 'big')
    base64url_str = base64.urlsafe_b64encode(byte_array).decode('utf-8')
    return base64url_str.rstrip('=')  

#jwks endpoint
@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    #serve jwks 
    jwks_keys = []
    now = datetime.utcnow()
    for kid, (public_key, _, expiration_time, expired) in keys.items():
        #checks to see if key is still valid
        if now <= expiration_time and not expired:
            public_numbers = public_key.public_numbers()
            jwks_keys.append({
                "kid": kid,
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "n": base64_encode(public_numbers.n),
                "e": "AQAB"
            })
    #valid keys are returned
    return jsonify(keys=jwks_keys)

#auth endpoint
@app.route('/auth', methods=['POST'])
def authenticate():
    #jwt is generated
    
    #chekcs to see if expired token is requested
    expired_param = request.args.get('expired', 'false')
    expired_param_lower = expired_param.lower()
    #expired token is generated
    expired = expired_param_lower == 'true'
    
    #new kid for the generated token
    key_id = generate_rsa_key(expired=expired)
    
    #private key for the generated token
    private_key = keys[key_id][1]
    
    #expiry time for jwt
    if expired:
        expiration_time = datetime.utcnow() - timedelta(minutes=1)
    else:
        expiration_time = datetime.utcnow() + timedelta(minutes=2)
    
    #test payload
    payload = {'username': 'ab2165', 'exp': expiration_time}
    
    #jwt encode
    try:
        token = jwt.encode(payload, private_key, algorithm='RS256', headers={'kid': key_id})
        return jsonify(token=token)
    except Exception as e:
        return jsonify({"error": "Valid key not found"}), 404

if __name__ == '__main__':
    app.run(port=8080)
