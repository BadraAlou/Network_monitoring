import requests

def geolocate_ip(ip):
    try:
        url = f"http://ip-api.com/json/{ip}"
        response = requests.get(url)
        data = response.json()
        if data["status"] == "success":
            return (data["lat"], data["lon"])
    except:
        pass
    return None
