from flask import Flask, render_template, request
import requests
import logging
import base64
import spotipy
import json
from spotipy import util
import hashlib
import secrets

# matan spotify : 21zdvzoitjsvxj7k2fyfflfwa
app = Flask(__name__)

logging.basicConfig(filename='app.log', level=logging.INFO)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/send_request_playlist', methods=['POST'])
def send_request_playlist():
    client_id = "7e22f4017769493cb09cfe94a751d51c"
    client_secret = "14a5a391ce36417a81b89ee9e4019c04"
    redirect_uri = "http://localhost:5000/"
    token_url = "https://accounts.spotify.com/api/token"
    data = { 'grant_type': 'client_credentials' }
   
    auth_header = base64.urlsafe_b64encode((client_id + ':' + client_secret).encode()).decode('utf-8')
    headers = {'Authorization': 'Basic %s' % auth_header}
    response = requests.post(token_url, data=data, headers=headers)

    access_token_dict = response.json()
    access_token = access_token_dict['access_token']
    #util here we got the token access

    #from here we are getting a playlist
    user_name = request.form['user_name']
    url = f'https://api.spotify.com/v1/users/{user_name}/playlists'        
    headers = {'Authorization': 'Bearer %s' % access_token}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        playlists_name_array = []
        for playlist in data['items']:
            playlists_name_array.append(playlist['name'])

        num_of_playlists = data['total']
        display_name = data['items'][0]['owner']['display_name']
        print("Hey " + display_name, end=" ")
        print("your plalyists in spotify are: ")
        print(playlists_name_array)

        #getting the tracks
        for playlist in data['items']:
            tracks_href = playlist['tracks']['href']
            url = tracks_href        
            headers = {'Authorization': 'Bearer %s' % access_token}
            response = requests.get(url, headers=headers)
            songs = response.json()
            print("For the playlist : " +playlist['name'] + " the songs are : ")
            for song in songs['items']:
                print(song['track']['name'])
    else:
        print('Request failed with status code:', response.status_code)

    return "Playlist Request sent successfully!"

@app.route('/add_new_playlist', methods=['POST'])
def add_new_playlist():
    client_id = "7e22f4017769493cb09cfe94a751d51c"
    client_secret = "14a5a391ce36417a81b89ee9e4019c04"
    redirect_uri = "http://localhost:5000/"
    token_url = "https://accounts.spotify.com/api/token"
    data = { 'grant_type': 'client_credentials' }

    auth_header = base64.urlsafe_b64encode((client_id + ':' + client_secret).encode()).decode('utf-8')
    headers = {'Authorization': 'Basic %s' % auth_header}
    response = requests.post(token_url, data=data, headers=headers)

    access_token_dict = response.json()
    access_token = access_token_dict['access_token']
    #util here we got the token access

    #from here we are posting a new playlist
    user_name = "dolevgabay"
    url = f'https://api.spotify.com/v1/users/{user_name}/playlists'        
    headers = {'Authorization': 'Bearer %s' % access_token}
    body = {'name': 'New Playlist', 'description': 'New playlist description', 'public': False}
    response = requests.post(url, headers=headers, json=body)
    if response.status_code == 200:
        print("here")
    else:
        print('Request failed with status code:', response.status_code)

    return "New Playlist Add Successfully!"


@app.route('/try_outh2', methods=['POST'])
def try_outh2():
    # define authorization server and endpoints
    authorization_server = 'https://accounts.spotify.com/api/token'
    token_endpoint = 'http://localhost:5000/'

    # define client credentials
    client_id = '7e22f4017769493cb09cfe94a751d51c'
    client_secret = '14a5a391ce36417a81b89ee9e4019c04'
    redirect_uri = 'http://localhost:5000/callback'

    # define scope and state
    scope = 'user-read-private user-read-email'
    state = secrets.token_hex(16)

    # generate code verifier and code challenge
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b'=').decode('utf-8')
    code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode('utf-8')).digest()).rstrip(b'=').decode('utf-8')

    # build authorization request
    authorization_request = authorization_server + '?' + \
        'response_type=code&' + \
        'client_id=' + client_id + '&' + \
        'redirect_uri=' + redirect_uri + '&' + \
        'scope=' + scope + '&' + \
        'state=' + state + '&' + \
        'code_challenge=' + code_challenge + '&' + \
        'code_challenge_method=S256'

    # redirect user to authorization request
    print('Redirect the user to:', authorization_request)

    # receive authorization code from callback
    authorization_code = input('Enter the authorization code: ')

    # exchange authorization code for access token
    token_response = requests.post(token_endpoint, data={
        'grant_type': 'authorization_code',
        'code': authorization_code,
        'redirect_uri': redirect_uri,
        'client_id': client_id,
        'code_verifier': code_verifier,
        'client_secret': client_secret,
    })

    # extract access token from response
    access_token = token_response.json()['access_token']
    print('Access token:', access_token)


if __name__ == '__main__':
    app.run(debug=True)
    
