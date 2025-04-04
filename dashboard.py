import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import msal
import webbrowser
from typing import Optional
import requests

# Configuration with expanded scopes
APP_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
SCOPES = [
    "User.Read",
    "Directory.Read.All",
    "UserAuthenticationMethod.Read.All",
    "AuditLog.Read.All",
    "Reports.Read.All",
    "Organization.Read.All",
    "User.ReadBasic.All"
]

class GraphAuth:
    def __init__(self):
        self.app = msal.PublicClientApplication(APP_ID)
    
    def get_token(self) -> Optional[str]:
        accounts = self.app.get_accounts()
        if accounts:
            result = self.app.acquire_token_silent(SCOPES, account=accounts[0])
            if result:
                return result['access_token']
        
        flow = self.app.initiate_device_flow(scopes=SCOPES)
        if 'user_code' not in flow:
            st.error('Failed to create device flow')
            return None

        st.markdown("### Microsoft Authentication Required")
        st.write("To access the MFA dashboard, please follow these steps:")
        st.code(flow['message'])
        
        webbrowser.open(flow['verification_uri'])
        
        result = self.app.acquire_token_by_device_flow(flow)
        
        if 'access_token' in result:
            return result['access_token']
        return None

def get_user_info(token):
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.get(
        'https://graph.microsoft.com/v1.0/me',
        headers=headers
    )
    if response.status_code == 200:
        return response.json()
    return None

def check_admin_roles(token):
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.get(
        'https://graph.microsoft.com/v1.0/me/memberOf',
        headers=headers
    )
    if response.status_code == 200:
        roles = response.json().get('value', [])
        admin_roles = ["Global Administrator", "Security Administrator", "Authentication Administrator"]
        return any(role['displayName'] in admin_roles for role in roles)
    return False

def get_mfa_status(token):
    headers = {'Authorization': f'Bearer {token}'}
    
    # Get all users with authentication methods
    response = requests.get(
        'https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,createdDateTime,signInActivity&$expand=authentication',
        headers=headers
    )
    
    if response.status_code != 200:
        return None
    
    users_data = response.json().get('value', [])
    mfa_data = []
    
    for user in users_data:
        authentication = user.get('authentication', {})
        methods = authentication.get('methods', [])
        
        mfa_status = "Disabled"
        if any(method['methodType'] != 'password' for method in methods):
            mfa_status = "Enabled"
            
        sign_in_activity = user.get('signInActivity', {})
        
        mfa_data.append({
            'DisplayName': user.get('displayName'),
            'UserPrincipalName': user.get('userPrincipalName'),
            'MFAStatus': mfa_status,
            'CreationDate': user.get('createdDateTime'),
            'LastSignInDate': sign_in_activity.get('lastSignInDateTime'),
            'LastNonInteractiveSignInDate': sign_in_activity.get('lastNonInteractiveSignInDateTime')
        })
    
    return pd.DataFrame(mfa_data)

def main():
    st.set_page_config(page_title="MFA Status Dashboard", layout="wide")
    
    if 'auth' not in st.session_state:
        st.session_state.auth = GraphAuth()
    
    if 'token' not in st.session_state:
        token = st.session_state.auth.get_token()
        if token:
            st.session_state.token = token
        else:
            st.error("Authentication failed")
            return
    
    if 'user_info' not in st.session_state:
        user_info = get_user_info(st.session_state.token)
        if user_info:
            st.session_state.user_info = user_info
        else:
            st.error("Failed to get user information")
            st.session_state.pop('token', None)
            st.experimental_rerun()
            return
    
    if 'is_admin' not in st.session_state:
        is_admin = check_admin_roles(st.session_state.token)
        st.session_state.is_admin = is_admin
    
    st.sidebar.markdown("### User Information")
    st.sidebar.write(f"Logged in as: {st.session_state.user_info.get('displayName')}")
    st.sidebar.write(f"Email: {st.session_state.user_info.get('userPrincipalName')}")
    
    if not st.session_state.is_admin:
        st.error("You don't have sufficient permissions to view MFA data.")
        if st.button("Logout"):
            for key in ['token', 'user_info', 'is_admin']:
                st.session_state.pop(key, None)
            st.experimental_rerun()
        return
    
    if st.sidebar.button("Logout"):
        for key in ['token', 'user_info', 'is_admin']:
            st.session_state.pop(key, None)
        st.experimental_rerun()
        return
    
    st.title("MFA Status Dashboard")
    st.markdown("---")

    if st.button("Refresh MFA Status"):
        with st.spinner("Fetching MFA status..."):
            df = get_mfa_status(st.session_state.token)
            if df is not None:
                st.session_state.mfa_data = df
            else:
                st.error("Failed to fetch MFA status")
                return

    if 'mfa_data' in st.session_state:
        df = st.session_state.mfa_data
        
        # Filters
        st.sidebar.title("Filters")
        
        mfa_status = st.sidebar.multiselect(
            "MFA Status",
            options=df['MFAStatus'].unique(),
            default=df['MFAStatus'].unique()
        )
        df = df[df['MFAStatus'].isin(mfa_status)]
        
        search = st.text_input("Search by name or email")
        if search:
            mask = df.apply(lambda x: x.astype(str).str.contains(search, case=False)).any(axis=1)
            df = df[mask]
        
        st.dataframe(df)
        
        if st.button("Export to CSV"):
            csv = df.to_csv(index=False)
            st.download_button(
                label="Download CSV",
                data=csv,
                file_name="mfa_status_export.csv",
                mime="text/csv"
            )

if __name__ == "__main__":
    main()