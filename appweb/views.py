from django.shortcuts import render
from django.http import HttpResponse
import requests, base64, json, random, hmac, hashlib, codecs


KEY_USER = '#####'
KEY_PASSWORD = '##########'
KEY_JS = '############'
KEY_SHA256 = '############'
URL_BASE = 'https://api.micuentaweb.pe/'

def index(request):
    data = request.POST
    return render(
        request,'inicio.html',
        {
            'formToken' : api_post(encriptado(),data['txt_name'],data['txt_lastname'],data['txt_email']),
            'url' : URL_BASE,
            'js_token' : KEY_JS
        }
    )

def respuesta(request):
    valores = request.POST
    jsonload = json.loads(valores['kr-answer'])
    respuestas = {
        'orderStatus' : jsonload['orderStatus'],
        'orderTotalAmount' : jsonload['orderDetails']['orderTotalAmount'],
        'orderId' : jsonload['orderDetails']['orderId'],
        'email' : jsonload['customer']['email']
    }
    return render(
        request,'respuesta.html',respuestas
    )

def validador(request):
    validador = request.POST
    print("VALOR %s"%validador['kr_hash_algorithm'])
    key = ""
    if "sha256_hmac" != validador['kr_hash_algorithm']:
        return HttpResponse(str('false'))
    krAnswer = validador['kr_answer'].replace("\/", "/")
    if validador['kr_hash_key'] == "sha256_hmac":
        key = KEY_SHA256
    elif validador['kr_hash_key'] == "password":
        key = KEY_PASSWORD
    else:
        return HttpResponse(str(False))
    calculatedHash = hmac.new(codecs.encode(key), msg=codecs.encode(krAnswer), digestmod=hashlib.sha256).hexdigest()
    if calculatedHash == validador['kr_hash']: return HttpResponse(str(json.dumps('true')))
    calculatedHash = hmac.new(codecs.encode(key), msg=codecs.encode(krAnswer.decode('string_escape')), digestmod=hashlib.sha256).hexdigest()
    if calculatedHash == validador['kr_hash']: return HttpResponse(str(json.dumps('true')))
    return HttpResponse(str(False))

def inicio_formulario(request):
    return render(request,'form.html',{})

def encriptado():
    data = KEY_USER + ':' + KEY_PASSWORD
    auth_basic = base64.b64encode(data.encode()).decode()
    print(auth_basic)
    return auth_basic

def api_post(valor,nombre,apellido,email):
    apunta = '/api-payment/V4/Charge/CreatePayment'
    header = {
        "Authorization" : 'Basic %s'%valor
    }
    body = {    
        "amount":   180, # 180 / 100
        "currency": "PEN",
        "orderId":  "MICUENTA-%s"%random.randrange(10000000,99999999),
        "customer": {
            "email": email,
            "billingDetails" : {
                "firstName" : nombre,
                "lastName" : apellido,
                "phoneNumber" : "987987654",
                "address" : "AV LIMA 123",
                "address2" : "AV LIMA 1234"
            }
        }
    }
    resp = requests.post(URL_BASE+apunta,json=body,headers=header)
    data = json.loads(resp.text)
    return data['answer']['formToken']