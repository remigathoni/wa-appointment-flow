from flask import Flask, request, jsonify
import os

app = Flask(__name__)


app.config.from_pyfile("config.py")
TOKEN = app.config.get("TOKEN")


@app.route("/", methods=["GET"])
def index():
    return "Hello, World!"


@app.route("/webhooks", methods=["GET"])
def webhooks():
    if (
        request.args.get("hub.mode") == "subscribe"
        and request.args.get("hub.verify_token") == TOKEN
    ):
        return jsonify({"hub": request.args.get("hub.challenge")}), 200
    else:
        return "Error, wrong validation token!", 400


# @app.route("/", methods=["POST"])
# def data(request):
#     try:
#         # Parse the request body
#         body = json.loads(request.body)

#         # Read the request field
#         encrypted_flow_data_b64 = body["encrypted_flow_data"]
#         encrypted_aes_key_b64 = body["encrypted_aes_key"]
#         initial_vector_b64 = body["initial_vector"]

#         decrypted_data, aes_key, iv = decrypt_request(
#             encrypted_flow_data_b64, encrypted_aes_key_b64, initial_vector_b64
#         )
#         print(decrypted_data)

#         # Return the next screen & data to the client
#         response = {
#             "version": decrypted_data["version"],
#             "screen": "CONFRIMATION_SCREEN",
#             "data": {"hello_world_text": "hello from endpoint"},
#         }

#         # Return the response as plaintext
#         return HTTPResponse(
#             encrypt_response(response, aes_key, iv), content_type="text/plain"
#         )
#     except Exception as e:
#         print(e)
#         return jsonify({"error": str(e)}), 500


# def decrypt_request(encrypted_flow_data_b64, encrypted_aes_key_b64, initial_vector_b64):
#     flow_data = b64decode(encrypted_flow_data_b64)
#     iv = b64decode(initial_vector_b64)

#     # Decrypt the AES encryption key
#     encrypted_aes_key = b64decode(encrypted_aes_key_b64)
#     private_key = load_pem_private_key(PRIVATE_KEY.encode("utf-8"), password=None)
#     aes_key = private_key.decrypt(
#         encrypted_aes_key,
#         OAEP(
#             mgf=MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
#         ),
#     )

#     # Decrypt the Flow data
#     encrypted_flow_data_body = flow_data[:-16]
#     encrypted_flow_data_tag = flow_data[-16:]
#     decryptor = Cipher(
#         algorithms.AES(aes_key), modes.GCM(iv, encrypted_flow_data_tag)
#     ).decryptor()
#     decrypted_data_bytes = (
#         decryptor.update(encrypted_flow_data_body) + decryptor.finalize()
#     )
#     decrypted_data = json.loads(decrypted_data_bytes.decode("utf-8"))
#     return decrypted_data, aes_key, iv


# def encrypt_response(response, aes_key, iv):
#     # Flip the initialization vector
#     flipped_iv = bytearray()
#     for byte in iv:
#         flipped_iv.append(byte ^ 0xFF)

#     # Encrypt the response data
#     encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(flipped_iv)).encryptor()
#     return b64encode(
#         encryptor.update(json.dumps(response).encode("utf-8"))
#         + encryptor.finalize()
#         + encryptor.tag
#     ).decode("utf-8")


if __name__ == "__main__":
    app.run(port=5000)
