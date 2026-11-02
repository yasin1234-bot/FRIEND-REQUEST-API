from flask import Flask, request, jsonify
import sys
import jwt
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import RemoveFriend_Req_pb2
from byte import Encrypt_ID, encrypt_api
import binascii
import time
import warnings
import urllib3
from datetime import datetime

# -----------------------------
# Security Warnings Disable
# -----------------------------
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore", category=UserWarning, message="Unverified HTTPS request")

app = Flask(__name__)

# -----------------------------
# AES Configuration
# -----------------------------
AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

def encrypt_message(data_bytes):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    return cipher.encrypt(pad(data_bytes, AES.block_size))

def encrypt_message_hex(data_bytes):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    encrypted = cipher.encrypt(pad(data_bytes, AES.block_size))
    return binascii.hexlify(encrypted).decode('utf-8')

# -----------------------------
# Region-based URL Configuration
# -----------------------------
def get_base_url(server_name):
    server_name = server_name.upper()
    if server_name == "IND":
        return "https://client.ind.freefiremobile.com/"
    elif server_name in {"BR", "US", "SAC", "NA"}:
        return "https://client.us.freefiremobile.com/"
    else:
        return "https://clientbp.ppmainecoonghj.com/"

# -----------------------------
# Token & Region Functions
# -----------------------------
def get_jwt_token_from_api(uid, password):
    # RGK JWT API — separate uid and password query params
    jwt_url = f"https://rgkjwtapi.vercel.app/token?uid={uid}&password={password}"

    try:
        response = requests.get(jwt_url, timeout=10)

        if response.status_code == 200:
            try:
                data = response.json()

                # Validate account status
                status = data.get('status', '')
                if status != 'live':
                    return None, None, f"Account status is not live: '{status}'"

                # Extract JWT token
                token = data.get('token')
                if not token:
                    return None, None, "Key 'token' not found in API response"

                # Extract region directly from API response (avoids redundant JWT decode)
                region = data.get('region', None)

                return token, region, None

            except ValueError:
                return None, None, "API response was not valid JSON"
        else:
            return None, None, f"API request failed with status {response.status_code}"

    except requests.exceptions.Timeout:
        return None, None, "Request timed out"
    except Exception as e:
        return None, None, str(e)

def get_region_from_jwt(jwt_token):
    try:
        decoded = jwt.decode(jwt_token, options={"verify_signature": False})
        lock_region = decoded.get('lock_region', 'BD')
        return lock_region.upper()
    except Exception as e:
        print(f"Region decode error: {e}")
        return 'BD'

def decode_author_uid(token):
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        return decoded.get("account_id") or decoded.get("sub")
    except:
        return None

# -----------------------------
# Authentication Resolver
# -----------------------------
def resolve_auth_details(args):
    """
    Returns: (token, author_uid, server_region, error_message)
    """
    token = args.get('token')
    
    # Case 1: Direct Token provided
    if token:
        auth_uid = decode_author_uid(token)
        region = get_region_from_jwt(token)
        if not auth_uid:
            return None, None, None, "Provided token is invalid (cannot decode UID)"
        return token, auth_uid, region, None
    
    # Case 2: UID and Password provided
    uid = args.get('uid')
    password = args.get('password')

    if uid and password:
        generated_token, api_region, error = get_jwt_token_from_api(uid, password)

        if error:
            return None, None, None, error

        if generated_token:
            auth_uid = decode_author_uid(generated_token)
            # Use region from API response if available, otherwise fall back to JWT decode
            region = api_region.upper() if api_region else get_region_from_jwt(generated_token)
            if not auth_uid:
                return None, None, None, "Generated token is invalid"
            return generated_token, auth_uid, region, None
    
    return None, None, None, "No credentials provided (token or uid/password)"

# -----------------------------
# Retry Decorator
# -----------------------------
def retry_operation(max_retries=10, delay=1):
    def decorator(func):
        def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_retries):
                try:
                    result = func(*args, **kwargs)
                    if result and result.get('status') in ['success', 'failed']:
                        return result
                    print(f"Attempt {attempt + 1}/{max_retries} failed, retrying...")
                except Exception as e:
                    last_exception = e
                    print(f"Attempt {attempt + 1}/{max_retries} failed with error: {str(e)}")
                
                if attempt < max_retries - 1:
                    time.sleep(delay)
            
            if last_exception:
                return {
                    "status": "error",
                    "message": f"All {max_retries} attempts failed",
                    "error": str(last_exception)
                }
            return {
                "status": "error", 
                "message": f"All {max_retries} attempts failed"
            }
        return wrapper
    return decorator

# -----------------------------
# Friend Management Functions
# -----------------------------
@retry_operation(max_retries=10, delay=1)
def remove_friend_with_retry(author_uid, target_uid, token, server_name):
    """Remove friend with retry mechanism"""
    try:
        msg = RemoveFriend_Req_pb2.RemoveFriend()
        msg.AuthorUid = int(author_uid)
        msg.TargetUid = int(target_uid)
        encrypted_bytes = encrypt_message(msg.SerializeToString())

        url = get_base_url(server_name) + "RemoveFriend"
        headers = {
            'Authorization': f"Bearer {token}",
            'User-Agent': "Dalvik/2.1.0 (Linux; Android 9)",
            'Content-Type': "application/x-www-form-urlencoded",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB55"
        }

        res = requests.post(url, data=encrypted_bytes, headers=headers, verify=False)
        
        if res.status_code == 200:
            status = "success"
        else:
            status = "failed"
            raise Exception(f"HTTP {res.status_code}: {res.text}")
        
        response_data = {
            "author_uid": author_uid,
            "uid": target_uid,
            "status": status,
            "region": server_name,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        return response_data

    except Exception as e:
        print(f"Remove friend error: {e}")
        raise e

@retry_operation(max_retries=10, delay=1)
def send_friend_request_with_retry(author_uid, target_uid, token, server_name):
    """Send friend request with retry mechanism"""
    try:
        encrypted_id = Encrypt_ID(target_uid)
        payload = f"08a7c4839f1e10{encrypted_id}1801"
        encrypted_payload = encrypt_api(payload)

        url = get_base_url(server_name) + "RequestAddingFriend"
        headers = {
            "Authorization": f"Bearer {token}",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB55",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Dalvik/2.1.0 (Linux; Android 9)"
        }

        r = requests.post(url, headers=headers, data=bytes.fromhex(encrypted_payload), verify=False)
        
        if r.status_code == 200:
            status = "success"
        else:
            status = "failed"
            raise Exception(f"HTTP {r.status_code}: {r.text}")
        
        response_data = {
            "author_uid": author_uid,
            "uid": target_uid,
            "status": status,
            "region": server_name,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        return response_data
        
    except Exception as e:
        print(f"Add friend error: {e}")
        raise e

# -----------------------------
# API Routes
# -----------------------------

@app.route('/add_friend', methods=['GET'])
def adding_friend_custom():
    """
    Supports:
    1. /add_friend?token={jwt_token}&target_uid={target_uid}
    2. /add_friend?uid={uid}&password={password}&target_uid={target_uid}
    """
    target_uid = request.args.get('target_uid') or request.args.get('friend_uid')
    
    if not target_uid:
        return jsonify({"status": "failed", "message": "Missing target_uid"}), 400

    # Resolve Authentication
    token, author_uid, server_name, error = resolve_auth_details(request.args)
    
    if error:
        return jsonify({"status": "failed", "message": error}), 400
    
    if not author_uid:
        return jsonify({"status": "failed", "message": "Invalid token content"}), 400

    result = send_friend_request_with_retry(author_uid, target_uid, token, server_name)
    return jsonify(result)

@app.route('/remove_friend', methods=['GET'])
def removing_friend_custom():
    """
    Supports:
    1. /remove_friend?token={jwt_token}&target_uid={target_uid}
    2. /remove_friend?uid={uid}&password={password}&target_uid={target_uid}
    """
    target_uid = request.args.get('target_uid') or request.args.get('friend_uid')

    if not target_uid:
        return jsonify({"status": "failed", "message": "Missing target_uid"}), 400

    # Resolve Authentication
    token, author_uid, server_name, error = resolve_auth_details(request.args)

    if error:
        return jsonify({"status": "failed", "message": error}), 400

    if not author_uid:
        return jsonify({"status": "failed", "message": "Invalid token content"}), 400

    result = remove_friend_with_retry(author_uid, target_uid, token, server_name)
    return jsonify(result)

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy", "service": "FreeFire-API"}), 200
    
    
@app.route('/', methods=['GET'])
def home():
    return jsonify({
        "message": "Welcome to the FF Friend Manager API",
        "service": "Free Fire Friend Request & Removal Service",
        "endpoints": {
            "/": "API Information",
            "/add": "Send a friend request to a target UID",
            "/remove": "Remove a friend by target UID",
            "/health": "Health check status"
        },
        "authentication": {
            "description": "You can authenticate using either a JWT token or UID/Password credentials.",
            "parameters": {
                "token": "JWT Bearer token (preferred)",
                "uid": "Account UID (if token is not provided)",
                "password": "Account Password (if token is not provided)"
            }
        },
        "common_parameters": {
            "target_uid": "The UID of the player to add or remove (alias: friend_uid)"
        },
        "examples": {
            "Add Friend with Credentials": "/add_friend?uid={uid}&password={password}&target_uid={target_uid}",
            "Add Friend with Token": "/add_friend?token={jwt_token}&target_uid={target_uid}",
            "Remove Friend with Credentials": "/remove_friend?uid={uid}&password={password}&target_uid={target_uid}",
            "Remove Friend with Token": "/remove_friend?token={jwt_token}&target_uid={target_uid}"
        }
    })

# -----------------------------
# Run Server
# -----------------------------

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)