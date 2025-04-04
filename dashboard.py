import streamlit as st
from datetime import datetime, timedelta
import sys

# Force SSL/HTTPS
st.set_page_config(
    page_title="MFA Status Dashboard",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        'Get Help': 'https://github.com/yourusername/your-repo',
        'Report a bug': 'https://github.com/yourusername/your-repo/issues',
        'About': 'MFA Status Dashboard v1.0'
    }
)

# Debug information
st.write("App version: 1.0")
st.write("Python version:", sys.version)
st.write("Streamlit version:", st.__version__)

try:
    import msal
    st.write("MSAL version:", msal.__version__)
except Exception as e:
    st.error(f"MSAL import error: {e}")

try:
    import pandas as pd
    st.write("Pandas version:", pd.__version__)
except Exception as e:
    st.error(f"Pandas import error: {e}")

import webbrowser
from typing import Optional
import requests
import traceback

# Configuration
APP_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
SCOPES = [
    "User.Read",
    "Directory.Read.All",
    "UserAuthenticationMethod.Read.All",
    "AuditLog.Read.All"
]

class GraphAuth:
    def __init__(self):
        try:
            self.app = msal.PublicClientApplication(APP_ID)
        except Exception as e:
            st.error(f"MSAL initialization error: {str(e)}")
            st.code(traceback.format_exc())
    
    def get_token(self) -> Optional[str]:
        try:
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
        except Exception as e:
            st.error(f"Authentication error: {str(e)}")
            st.code(traceback.format_exc())
            return None

def get_user_info(token):
    try:
        headers = {'Authorization': f'Bearer {token}'}
        response = requests.get(
            'https://graph.microsoft.com/v1.0/me',
            headers=headers
        )
        if response.status_code == 200:
            return response.json()
        st.error(f"API Error: {response.status_code} - {response.text}")
        return None
    except Exception as e:
        st.error(f"User info error: {str(e)}")
        st.code(traceback.format_exc())
        return None

def get_mfa_status(token):
    try:
        headers = {'Authorization': f'Bearer {token}'}
        
        users_response = requests.get(
            'https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,createdDateTime,signInActivity',
            headers=headers
        )
        
        if users_response.status_code != 200:
            st.error(f"Users API Error: {users_response.status_code} - {users_response.text}")
            return None
        
        users_data = users_response.json().get('value', [])
        mfa_data = []
        
        thirty_days_ago = (datetime.utcnow() - timedelta(days=30)).isoformat() + 'Z'
        
        for user in users_data:
            try:
                auth_methods_response = requests.get(
                    f'https://graph.microsoft.com/v1.0/users/{user["id"]}/authentication/methods',
                    headers=headers
                )
                
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
            except Exception as e:
                st.error(f"Error processing user {user.get('userPrincipalName')}: {str(e)}")
                continue
        
        return pd.DataFrame(mfa_data)
    except Exception as e:
        st.error(f"MFA status error: {str(e)}")
        st.code(traceback.format_exc())
        return None

def main():
    st.title("MFA Status Dashboard")
    
    # Initialize authentication
    if 'auth' not in st.session_state:
        st.session_state.auth = GraphAuth()
    
    # Get or refresh token
    if 'token' not in st.session_state:
        token = st.session_state.auth.get_token()
        if token:
            st.session_state.token = token
        else:
            st.error("Authentication failed")
            return
    
    # Get user info
    if 'user_info' not in st.session_state:
        user_info = get_user_info(st.session_state.token)
        if user_info:
            st.session_state.user_info = user_info
        else:
            st.error("Failed to get user information")
            st.session_state.pop('token', None)
            st.experimental_rerun()
            return

    # Show user info
    st.sidebar.markdown("### User Information")
    st.sidebar.write(f"Logged in as: {st.session_state.user_info.get('displayName')}")
    st.sidebar.write(f"Email: {st.session_state.user_info.get('userPrincipalName')}")
    
    if st.sidebar.button("Logout"):
        for key in ['token', 'user_info']:
            st.session_state.pop(key, None)
        st.experimental_rerun()
        return
    
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
    try:
        main()
    except Exception as e:
        st.error(f"Application error: {str(e)}")
        st.code(traceback.format_exc())