import requests
from datetime import datetime
import sqlite3 
import time

# connect to the database
db = sqlite3.connect('./instance/database.db')

def call_urls():
        print('Sending requests...')
        urls = db.execute('Select * from url').fetchall()
        print('URLs:', urls)
        for url in urls:
            address = url[1]
            if address[:4] != 'http' or address[:5] != 'https':
                address = 'https://' + address
            try:
                result = requests.get(address)
                status = result.status_code
            except:
                print('Error: Could not get response from', address)
                status = 777 # 777 is a custom error code for a failed request
            
            date = datetime.now()
            query = f'Insert into request (url_id, result, timestamp) values ({url[0]}, {status}, "{date}")'
            
            db.execute(query)
            db.commit()


  
print('Starting scheduler...')
while True: 
  call_urls()
  time.sleep(5)