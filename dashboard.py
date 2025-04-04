import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import msal
import webbrowser
from typing import Optional
import requests

# Configuration with your available permissions
APP_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
SCOPES = [
    "User.Read",
    "Directory.Read.All",
    "UserAuthenticationMethod.Read.All",
    "AuditLog.Read.All"
]

def get_mfa_status(token):
    headers = {'Authorization': f'Bearer {token}'}
    
    # Get users with basic info
    users_response = requests.get(
        'https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,createdDateTime,signInActivity',
        headers=headers
    )
    
    if users_response.status_code != 200:
        st.error("Failed to fetch users")
        return None
    
    users_data = users_response.json().get('value', [])
    mfa_data = []
    
    # Get sign-in logs for last 30 days
    thirty_days_ago = (datetime.utcnow() - timedelta(days=30)).isoformat() + 'Z'
    
    for user in users_data:
        # Get authentication methods for each user
        auth_methods_response = requests.get(
            f'https://graph.microsoft.com/v1.0/users/{user["id"]}/authentication/methods',
            headers=headers
        )
        
        # Get recent sign-ins
        sign_ins_response = requests.get(
            f'https://graph.microsoft.com/v1.0/auditLogs/signIns?$filter=userId eq \'{user["id"]}\' and createdDateTime gt {thirty_days_ago}&$top=1&$orderby=createdDateTime desc',
            headers=headers
        )
        
        mfa_status = "Disabled"
        auth_methods = []
        last_sign_in = None
        
        if auth_methods_response.status_code == 200:
            methods = auth_methods_response.json().get('value', [])
            auth_methods = [m.get('methodType', '') for m in methods]
            if any(method != 'password' for method in auth_methods):
                mfa_status = "Enabled"
        
        if sign_ins_response.status_code == 200:
            sign_ins = sign_ins_response.json().get('value', [])
            if sign_ins:
                last_sign_in = sign_ins[0].get('createdDateTime')
        
        mfa_data.append({
            'DisplayName': user.get('displayName'),
            'UserPrincipalName': user.get('userPrincipalName'),
            'MFAStatus': mfa_status,
            'AuthMethods': ', '.join(auth_methods) if auth_methods else 'None',
            'CreationDate': user.get('createdDateTime'),
            'LastSignIn': last_sign_in,
            'LastInteractiveSignIn': user.get('signInActivity', {}).get('lastSignInDateTime'),
            'LastNonInteractiveSignIn': user.get('signInActivity', {}).get('lastNonInteractiveSignInDateTime')
        })
    
    return pd.DataFrame(mfa_data)