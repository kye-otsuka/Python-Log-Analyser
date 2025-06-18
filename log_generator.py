import random
from datetime import datetime
import os

## random fake data for test
def generate_logs(lines):
    ip_addresses = ["192.168.1.1", "172.1.5.3", "192.168.0.57", "127.0.0.1"]
    statuses = ['200', '404', '403', '429']
    paths = ["/login", "/admin", "/index.html", "/dashboard"]
    request_Types = ["POST", "GET", "DELETE", "PUT", "HEAD"]

    ## create the file
    with open("access.log", "w") as f:
        for _ in range(lines):
            # print(_)
            ## randomise synthtic data from our generator 
            ip_address = random.choice(ip_addresses)
            status = random.choice(statuses)
            path = random.choice(paths)
            request_Type = random.choice(request_Types)

            ## assign a set time
            now = datetime.now().strftime('%d/%b/%Y:%H:%M:%S +0000')
            line = f'{ip_address} -- [{now}] "{request_Type} {path} HTTP/1.1" {status} 512\n'
            f.write(line) ## write to the files

     