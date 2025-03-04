import base64
import hashlib
from io import BytesIO

import requests
import streamlit as st


def calculate_hash(file, hash_type):
    hash_func = getattr(hashlib, hash_type)()
    
    for chunk in iter(lambda: file.read(4096), b""):
        hash_func.update(chunk)
    
    hash_bytes = hash_func.digest()
    hash_base64 = base64.b64encode(hash_bytes).decode('utf-8')
    
    return hash_base64

st.title("File Hash Calculator (Base64)")

hash_options = ["sha256", "sha1", "md5"]
selected_hash = st.selectbox("Select Hash Algorithm", hash_options)

uploaded_files = st.file_uploader("Upload files", type=None, accept_multiple_files=True)
file_url = st.text_input("Enter file URL")

if uploaded_files:
    for uploaded_file in uploaded_files:
        hash_result = calculate_hash(uploaded_file, selected_hash)
        st.write(f"File: {uploaded_file.name}")
        st.write(f"{selected_hash}-{hash_result}")

if file_url:
    try:
        response = requests.get(file_url, stream=True)
        response.raise_for_status()
        file_stream = BytesIO(response.content)
        hash_result = calculate_hash(file_stream, selected_hash)
        st.write(f"URL: {file_url}")
        st.write(f"{selected_hash}-{hash_result}")
    except requests.exceptions.RequestException as e:
        st.error(f"Error fetching file: {e}")

# check out https://emn178.github.io/online-tools/sha256_checksum.html
