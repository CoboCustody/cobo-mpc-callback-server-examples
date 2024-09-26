# This is a sample Python script.

# Press ⌃R to execute it or replace it with your code.
# Press Double ⇧ to search everywhere for classes, files, tool windows, actions, and settings.


# System imports
from pathlib import Path
# Third-party imports
import falcon
from falcon import media
import jwt
from wsgiref.simple_server import make_server
from pymarshaler.marshal import Marshal
from datetime import datetime, timedelta
import json
import base64
import calendar

StatusOK = 0
StatusInvalidRequest = 10
StatusInvalidToken = 20
StatusInternalError = 30
marshal = Marshal(ignore_unknown_fields=True)


class PackageDataClaim:
    def __init__(self, package_data: str, aud: str = None, exp: int = None, jti: str = None, iat: int = None,
                 iss: str = None, nbf: int = None, sub: str = None):
        self.package_data = package_data
        if aud is not None: self.aud = aud
        if exp is not None: self.exp = exp
        if jti is not None: self.jti = jti
        if iat is not None: self.iat = iat
        if iss is not None: self.iss = iss
        if nbf is not None: self.nbf = nbf
        if sub is not None: self.sub = sub


class CallBackRequest:
    def __init__(self, request_type: int, request_id: str, request_detail: str, extra_info: str):
        self.request_type = request_type
        self.request_id = request_id
        self.request_detail = request_detail
        self.extra_info = extra_info


class CallBackResponse:
    def __init__(self, status: int, request_id: str = None, action: str = None, error: str = None):
        self.status = status
        self.request_id = request_id
        self.action = action
        self.error = error


class CallBackService(object):
    def __init__(self, service_name: str, token_expired_minutes: int, callback_pubkey_path: str,
                 callback_handler_prikey_path: str):
        self.form_data = {}
        self.service_name = service_name
        self.token_expired_minutes = token_expired_minutes

        cs_pub = Path(callback_pubkey_path)
        if cs_pub.is_file():
            self.CallBackPubKey = cs_pub.read_bytes()
        # TODO: throw out an error or panic if not file

        cb_pri = Path(callback_handler_prikey_path)
        if cb_pri.is_file():
            self.CallBackHandlerPriKey = cb_pri.read_bytes()

    def send_response(self, resp, cbRsp: CallBackResponse):
        message = marshal.marshal(cbRsp).decode()

        message_bytes = message.encode('ascii')
        base64_bytes = base64.b64encode(message_bytes)
        base64_message = base64_bytes.decode('ascii')

        exp = datetime.utcnow() + timedelta(minutes=self.token_expired_minutes)
        claim = PackageDataClaim(package_data=base64_message, iss=self.service_name,
                                 exp=calendar.timegm(exp.utctimetuple()))

        resp.text = jwt.encode(claim.__dict__, self.CallBackHandlerPriKey, algorithm="RS256")
        resp.status = falcon.HTTP_200
        return

    def parse_form_data(self, req):
        self.form_data = req.get_media()

    def on_post_check(self, req, resp):
        self.parse_form_data(req)
        jwt_token = self.form_data["TSS_JWT_MSG"]
        if jwt_token:
            try:
                options = {'verify_exp': True}
                payload = jwt.decode(jwt_token, self.CallBackPubKey, algorithms=["RS256"], options=options)
            except (jwt.DecodeError, jwt.ExpiredSignatureError):
                self.send_response(resp, CallBackResponse(status=StatusInvalidToken, error="Invalid token"))
                return

            claims = marshal.unmarshal(PackageDataClaim, payload)
            base64_bytes = claims.package_data.encode('ascii')
            message_bytes = base64.b64decode(base64_bytes)
            message = message_bytes.decode('ascii')

            cb_req = marshal.unmarshal(CallBackRequest, json.loads(message))
            if cb_req.request_type == 1:
                self.process_keygen_request(cb_req.request_id, cb_req.request_detail, cb_req.extra_info, resp)
            elif cb_req.request_type == 2:
                self.process_keysign_request(cb_req.request_id, cb_req.request_detail, cb_req.extra_info, resp)
            elif cb_req.request_type == 3:
                self.process_keyreshare_request(cb_req.request_id, cb_req.request_detail, cb_req.extra_info, resp)
            elif cb_req.request_type == 0:
                self.process_ping_request(cb_req.request_id, resp)
            else:
                self.send_response(resp, CallBackResponse(status=StatusInvalidRequest, error="Invalid request data type"))
            return
        else:
            self.send_response(resp, CallBackResponse(status=StatusInvalidRequest, error="Auth token required"))
            return
        
    def process_ping_request(self, reqiest_id: str, resp):
        self.send_response(resp, CallBackResponse(status=StatusOK, request_id=reqiest_id))
        return
    
    def process_keygen_request(self, request_id: str, request_detail: str, extra_info: str, resp):
        # key_gen_detail = marshal.unmarshal(KeyGenDetail, json.loads(request_detail))
        # raw_extra_info = marshal.unmarshal(KeyGenExtraInfo, json.loads(extra_info))

        # risk control logical

        self.send_response(resp, CallBackResponse(status=StatusOK, request_id=request_id,
                                                  action="APPROVE"))
        return

    def process_keysign_request(self, request_id: str, request_detail: str, extra_info: str, resp):
        # key_sign_detail = marshal.unmarshal(KeySignDetail, json.loads(request_detail))
        # raw_extra_info = marshal.unmarshal(KeySignExtraInfo, json.loads(extra_info))

        # risk control logical

        self.send_response(resp, CallBackResponse(status=StatusOK, request_id=request_id,
                                                  action="APPROVE"))
        return

    def process_keyreshare_request(self, request_id: str, request_detail: str, extra_info: str, resp):
        # key_reshare_detail = marshal.unmarshal(KeyReshareDetail, json.loads(request_detail))
        # raw_extra_info = marshal.unmarshal(KeyReshareExtraInfo, json.loads(extra_info))

        # risk control logical

        self.send_response(resp, CallBackResponse(status=StatusOK, request_id=request_id,
                                                  action="APPROVE"))
        return

# Create falcon app
app = falcon.App()

extra_handlers = {
    falcon.MEDIA_MULTIPART: media.MultipartFormHandler(),
}
app.req_options.media_handlers.update(extra_handlers)

cbService = CallBackService(service_name="TEST-001", token_expired_minutes=2, callback_pubkey_path="./cobo-tss-node-risk-control-pub.key",
                            callback_handler_prikey_path="./callback-server-pri.pem")

app.add_route('/v1/check', cbService, suffix='check')

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    with make_server('', 11020, app) as httpd:
        print('Serving on port 11020...')

        # Serve until process is killed
        httpd.serve_forever()
