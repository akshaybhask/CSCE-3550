from flask import Flask, jsonify, request
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
import jwt
import uuid

app = Flask(__name__)

# Function to generate RSA key pair
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    # Serialize keys to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem.decode('utf-8'), public_pem.decode('utf-8')

# Generate initial key pair
private_key, public_key = generate_rsa_key_pair()

# Key metadata including kid, expiration time, and algorithm
key_metadata = {
    'kid': str(uuid.uuid4()),
    'exp': int((datetime.utcnow() + timedelta(days=30)).timestamp()),
    'alg': 'RS256'
}

# Route to serve JWKS endpoint
@app.route('/jwks', methods=['GET'])
def jwks():
    if datetime.utcnow().timestamp() > key_metadata['exp']:
        # Regenerate key pair if expired
        global private_key, public_key, key_metadata
        private_key, public_key = generate_rsa_key_pair()
        key_metadata = {
            'kid': str(uuid.uuid4()),
            'exp': int((datetime.utcnow() + timedelta(days=30)).timestamp()),
            'alg': 'RS256'
        }
    return jsonify({'keys': [key_metadata]})

# Route to serve authentication endpoint
@app.route('/auth', methods=['POST'])
def authenticate():
    expired = 'expired' in request.args and request.args['expired'] == 'true'
    key_to_use = key_metadata if not expired else {
        'kid': key_metadata['kid'],
        'exp': int((datetime.utcnow() - timedelta(days=30)).timestamp()),  # Expired key
        'alg': 'RS256'
    }

    token = jwt.encode({}, private_key, algorithm='RS256', headers={'kid': key_to_use['kid']})
    return jsonify({'token': token})

if __name__ == '__main__':
    app.run(port=8080, debug=True)
