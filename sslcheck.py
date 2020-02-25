import ssl
from datetime import datetime
import OpenSSL
import socket
from datetime import timedelta
import json



def https_check():
   cur_date = datetime.utcnow()
   alert_body=""
   expired_count=0
   expday=4000
   with open('connection_test.json') as json_data_file:
      data = json.load(json_data_file)

   for url in data['connectivity']['https'] :
      host = url
      try:
         if data['connectivity']['https'][url]['production_port']:
            port = data['connectivity']['https'][url]['production_port']
      except:
         port = data['connectivity']['production_port']
         try:
            print("Checking certifcate for server ",host)
            ctx = OpenSSL.SSL.Context(ssl.PROTOCOL_TLSv1)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, int(port)))
            cnx = OpenSSL.SSL.Connection(ctx, s)
            cnx.set_connect_state()
            cnx.do_handshake()
            cert=cnx.get_peer_certificate()
            s.close()
            edate=cert.get_notAfter()
            edate=edate.decode()
            exp_date = datetime.strptime(edate,'%Y%m%d%H%M%SZ')
            days_to_expire = int((exp_date - cur_date).days)

            if days_to_expire < int(expday) :
                  expired_count=expired_count+1
                  alert_body=alert_body+"\n Server name ="+host+", Days to expire:"+str(days_to_expire)      
         
         except:
            print ("error on connection to Server,",host)
         print (alert_body)

      #sending alert if any certificate going to expire within threshold days
   if expired_count >= 1 :
      try:
         print("\nCertifcate alert for "+str(expired_count)+" Servers!")       
               ##SEND alert
      except:
         print ("Sending mail failed")
   else :
         print("All certificates are below the threshold date")
               
https_check()