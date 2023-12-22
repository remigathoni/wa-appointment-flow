from datetime import datetime, timedelta
import json
import os
from flask import Flask, Response, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import requests
from base64 import b64decode, b64encode
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1, hashes
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import traceback

app = Flask(__name__)

# Configure database
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///appointments.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# Get env variables
WA_PHONENUMBER_ID = os.environ.get("WA_PHONENUMBER_ID")
ACCESS_TOKEN = os.environ.get("ACCESSTOKEN")
FLOW_TOKEN = os.environ.get("FLOW_TOKEN")
FLOW_ID = os.environ.get("FLOW_ID")

VERIFICATION_TOKEN = os.environ.get("VERIFICATIONTOKEN")
PRIVATE_KEY = os.environ.get("PRIVATEKEY")


# Function to convert timestamp to Python datetime object
def convert_timestamp_to_datetime(timestamp_str):
    timestamp_seconds = int(timestamp_str) / 1000
    datetime_object = datetime.fromtimestamp(timestamp_seconds)
    date = datetime_object.strftime("%Y-%m-%d")
    return date


class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(50), nullable=False)
    wa_id = db.Column(db.String(50), nullable=False)
    date = db.Column(db.String(50), nullable=False)
    details = db.Column(db.Text)

    def to_dict(self):
        return {
            "id": self.id,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "email": self.email,
            "wa_id": self.wa_id,
            "date": convert_timestamp_to_datetime(self.date),
            "details": self.details,
        }


# Create the database table if it doesn't exist when app starts
with app.app_context():
    db.create_all()


# Function to check appointment date availability
def is_date_available(new_date):
    return Appointment.query.filter_by(date=new_date).first() is None


# Function to save appointments to the SQLite database
def save_appointment_to_db(appointment):
    db.session.add(appointment)
    db.session.commit()


# Function to load appointments from the SQLite database
def get_all_appointments_from_db():
    appointments = Appointment.query.all()
    return [appointment.to_dict() for appointment in appointments]


# Available appointment dates
def get_min_date_timestamp():
    # Get the current date and time as the minimum allowed date
    min_date = datetime.today()
    print(min_date)
    # Convert to timestamp in milliseconds
    min_date_timestamp_seconds = int(min_date.timestamp() * 1000)

    return str(min_date_timestamp_seconds)


def get_max_date_timestamp(days_in_future=30):
    # Get the current date and time as the maximum allowed date
    max_date = datetime.now() + timedelta(days=days_in_future)

    # Convert to timestamp in milliseconds
    max_date_timestamp_seconds = int(max_date.timestamp() * 1000)
    return str(max_date_timestamp_seconds)


# Function to create an appointment and add it to the SQLite database
def create_appointment(data=None):
    try:
        date = data["date"]
        first_name = data["first_name"]
        last_name = data["last_name"]
        details = data["appt_details"]
        email = data["email"]
        wa_id = data["wa_id"]

        # Check appointment date availability
        if not is_date_available(date):
            return {"error": "Appointment date not available"}

        # If date is available, create and add the appointment to the database
        appointment = Appointment(
            first_name=first_name,
            last_name=last_name,
            email=email,
            wa_id=wa_id,
            date=date,
            details=details,
        )
        save_appointment_to_db(appointment)
        return {"error": None}
    except Exception as e:
        return {"error": str(e)}


# Send flow
@app.route("/send-flow", methods=["POST"])
def send_appointment():
    try:
        data = request.get_json()
        recipient_wa_id = data["recipient_wa_id"]
        send_appointment_flow(recipient_wa_id)
        return {"Message": "Flow sent successfully!"}, 200
    except Exception as e:
        print(e)
        return jsonify({"error": str(e)}), 500


def send_appointment_flow(recipient_wa_id):
    try:
        payload = {
            "recipient_type": "individual",
            "messaging_product": "whatsapp",
            "to": recipient_wa_id,
            "type": "interactive",
            "interactive": {
                "type": "flow",
                "body": {"text": "Schedule a free consultation!"},
                "action": {
                    "name": "flow",
                    "parameters": {
                        "flow_message_version": "3",
                        "flow_token": FLOW_TOKEN,
                        "mode": "draft",
                        "flow_id": "386176477091225",
                        "flow_cta": "Book an appointment!",
                        "flow_action": "navigate",
                        "flow_action_payload": {
                            "screen": "APPOINTMENT_SCREEN",
                            "data": {
                                "min_date": get_min_date_timestamp(),
                                "max_date": get_max_date_timestamp(),
                            },
                        },
                    },
                },
            },
        }

        graph_api_url = f"https://graph.facebook.com/v18.0/{WA_PHONENUMBER_ID}/messages"
        headers = {
            "Authorization": "Bearer " + ACCESS_TOKEN,
            "Content-Type": "application/json",
        }
        response = requests.post(graph_api_url, headers=headers, json=payload)
        res = response.json()
        if res["messages"][0]["id"] is not None:
            return True
        else:
            return False
    except Exception as e:
        print(e)
        return False


# Endpoint configuration
@app.route("/", methods=["POST"])
def data():
    try:
        # Parse the request body
        body = request.get_json()

        # Read the request fields
        encrypted_flow_data_b64 = body["encrypted_flow_data"]
        encrypted_aes_key_b64 = body["encrypted_aes_key"]
        initial_vector_b64 = body["initial_vector"]

        decrypted_data, aes_key, iv = decrypt_request(
            encrypted_flow_data_b64, encrypted_aes_key_b64, initial_vector_b64
        )
        print(decrypted_data)

        # Return the next screen & data to the client
        response = {
            "version": decrypted_data["version"],
            "screen": "SCREEN_NAME",
            "data": {"some_key": "some_value"},
        }
        # Return the response as plaintext
        return Response(
            encrypt_response(response, aes_key, iv), content_type="text/plain"
        )
    except Exception as e:
        return Response({}, status=500)


def decrypt_request(encrypted_flow_data_b64, encrypted_aes_key_b64, initial_vector_b64):
    try:
        flow_data = b64decode(encrypted_flow_data_b64)
        iv = b64decode(initial_vector_b64)

        # Decrypt the AES encryption key
        encrypted_aes_key = b64decode(encrypted_aes_key_b64)
        private_key = load_pem_private_key(
            PRIVATE_KEY.encode("utf-8"), password="pass".encode("utf-8")
        )
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            OAEP(
                mgf=MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        # Decrypt the Flow data
        encrypted_flow_data_body = flow_data[:-16]
        encrypted_flow_data_tag = flow_data[-16:]
        decryptor = Cipher(
            algorithms.AES(aes_key), modes.GCM(iv, encrypted_flow_data_tag)
        ).decryptor()
        decrypted_data_bytes = (
            decryptor.update(encrypted_flow_data_body) + decryptor.finalize()
        )
        decrypted_data = json.loads(decrypted_data_bytes.decode("utf-8"))
        return decrypted_data, aes_key, iv
    except Exception as e:
        print(traceback.format_exc())
        return {}, None, None


def encrypt_response(response, aes_key, iv):
    # Flip the initialization vector
    flipped_iv = bytearray()
    for byte in iv:
        flipped_iv.append(byte ^ 0xFF)

    # Encrypt the response data
    encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(flipped_iv)).encryptor()
    return b64encode(
        encryptor.update(json.dumps(response).encode("utf-8"))
        + encryptor.finalize()
        + encryptor.tag
    ).decode("utf-8")


# Send confirmation message
def send_confirmation_message(recipient_wa_id, message):
    payload = {
        "messaging_product": "whatsapp",
        "recipient_type": "individual",
        "to": recipient_wa_id,
        "type": "text",
        "text": {"preview_url": False, "body": message},
    }

    graph_api_url = f"https://graph.facebook.com/v18.0/{WA_PHONENUMBER_ID}/messages"
    headers = {
        "Authorization": "Bearer " + ACCESS_TOKEN,
        "Content-Type": "application/json",
    }
    requests.post(graph_api_url, headers=headers, json=payload)


# Webhook configuration - not using this will remove


# @app.route("/webhooks", methods=["GET"])
# def webhooks():
#     # Verify the webhook
#     if (
#         request.args.get("hub.mode") == "subscribe"
#         and request.args.get("hub.verify_token") == VERIFICATION_TOKEN
#     ):
#         return request.args.get("hub.challenge"), 200
#     else:
#         return "Error, wrong validation token!", 400


# @app.route("/webhooks", methods=["POST"])
# def book_appointments():
#     try:
#         data = request.get_json()

#         response = data["entry"][0]["changes"][0]["value"]["messages"][0]
#         contents = response["interactive"]["nfm_reply"]["response_json"]

#         # Check if the flow message is from the appointment Flow
#         flow_token = contents["flow_token"]
#         from_wa_id = response["from"]
#         if flow_token != FLOW_TOKEN:
#             # Not a flow message, so don't process
#             return "Not the appointment flow", 400

#         new_appointment_details = {
#             "date": contents["date"],
#             "first_name": contents["first_name"],
#             "last_name": contents["last_name"],
#             "details": contents["appt_details"],
#             "email": contents["email"],
#             "wa_id": from_wa_id,
#         }
#         new_appointment = create_appointment(new_appointment_details)
#         if new_appointment["error"] is None:
#             # Send confirmation message
#             send_confirmation_message(
#                 from_wa_id, "Could not book appointment. Slot already taken."
#             )
#             return jsonify({"error": new_appointment["error"]}), 400
#         send_confirmation_message(
#             from_wa_id, "You have successfully booked your appointment!"
#         )
#         return "Success", 200
#     except Exception as e:
#         print(e)
#         return jsonify({"error": str(e)}), 500
