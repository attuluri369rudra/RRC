import os
from time import sleep
import os

# #while 1:
# #    print(os.listdir('/.')) #do something here. in this sample, it prints the current directory 
# #    sleep(60) #delay for 60 seconds before it goes back to do something
# import pcap

# # Open a live network interface for capturing traffic
# pc = pcap.pcap()
# print(pc)
# # Loop through the captured packets
# for ts, pkt in pc:
#     print("entered the loop")
#     # Process the packet here
#     print(pkt)
import requests
from mitmproxy import http

def check_url(url, api_key):
    # VirusTotal API endpoint
    url_vt = 'https://www.virustotal.com/vtapi/v2/url/report'

    # Parameters to be sent to the VirusTotal API
    params = {'apikey': api_key, 'resource': url}

    # Send a request to the VirusTotal API
    response = requests.get(url_vt, params=params)

    # Parse the JSON response
    json_response = response.json()

    # Check if the URL is safe
    if json_response['response_code'] == 1:
        if json_response['positives'] > 0:
            return False
        else:
            return True
    else:
        return False

class CheckURL:
    def __init__(self):
        self.api_key = 'YOUR_VIRUSTOTAL_API_KEY'

    def request(self, flow: http.HTTPFlow) -> None:
        url = flow.request.pretty_url
        if check_url(url, self.api_key):
            print(f'Access granted: {url}')
        else:
            print(f'Access denied: {url}')
            flow.response = http.HTTPResponse.make(
                403, b"Access denied by firewall",
            )
            