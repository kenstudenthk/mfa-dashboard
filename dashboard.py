import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import msal
import webbrowser
from typing import Optional
import requests

# Simple configuration - no need for client secret
APP_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"  # Microsoft Graph PowerShell default app ID
SCOPES = ["User.Read", "Directory.Read.All"]

class GraphAuth:
    def __init__(self):
        self.app = msal.PublicClientApplication(APP_ID)
    
    def get_token(self) -> Optional[str]:
        # Check cached token first
        accounts = self.app.get_accounts()
        if accounts:
            result = self.app.acquire_token_silent(SCOPES, account=accounts[0])
            if result:
                return result['access_token']
        
        # If no cached token, start interactive login
        flow = self.app.initiate_device_flow(scopes=SCOPES)
        if 'user_code' not in flow:
            st.error('Failed to create device flow')
            return None

        # Show login instructions
        st.markdown("### Microsoft Authentication Required")
        st.write("To access the MFA dashboard, please follow these steps:")
        st.code(flow['message'])
        
        # Open browser automatically
        webbrowser.open(flow['verification_uri'])
        
        # Wait for user to complete login
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

def main():
    st.set_page_config(page_title="MFA Status Dashboard", layout="wide")
    
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
    
    # Get user info once authenticated
    if 'user_info' not in st.session_state:
        user_info = get_user_info(st.session_state.token)
        if user_info:
            st.session_state.user_info = user_info
        else:
            st.error("Failed to get user information")
            st.session_state.pop('token', None)
            st.experimental_rerun()
            return
    
    # Check admin roles
    if 'is_admin' not in st.session_state:
        is_admin = check_admin_roles(st.session_state.token)
        st.session_state.is_admin = is_admin
    
    # Show user info in sidebar
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
    
    # Logout button
    if st.sidebar.button("Logout"):
        for key in ['token', 'user_info', 'is_admin']:
            st.session_state.pop(key, None)
        st.experimental_rerun()
        return
    
    # Main dashboard content
    st.title("MFA Status Dashboard")
    st.markdown("---")

    # File upload
    file_path = st.file_uploader("Upload CSV file", type=['csv'])
    
    if file_path is not None:
        try:
            df = pd.read_csv(file_path)
            
            # Convert date columns
            date_columns = ['CreationDate', 'LastInteractiveSignInDate', 'LastNonInteractiveSignInDate']
            for col in date_columns:
                if col in df.columns:
                    df[col] = pd.to_datetime(df[col], errors='coerce')
            
            # Filters
            st.sidebar.title("Filters")
            
            # MFA Status filter
            if 'MFAStatus' in df.columns:
                mfa_status = st.sidebar.multiselect(
                    "MFA Status",
                    options=df['MFAStatus'].unique(),
                    default=df['MFAStatus'].unique()
                )
                df = df[df['MFAStatus'].isin(mfa_status)]
            
            # Search filter
            search = st.text_input("Search by name or email")
            if search:
                mask = df.apply(lambda x: x.astype(str).str.contains(search, case=False)).any(axis=1)
                df = df[mask]
            
            # Display data
            st.dataframe(df)
            
            # Export button
            if st.button("Export to CSV"):
                csv = df.to_csv(index=False)
                st.download_button(
                    label="Download CSV",
                    data=csv,
                    file_name="mfa_status_export.csv",
                    mime="text/csv"
                )
                
        except Exception as e:
            st.error(f"Error processing file: {str(e)}")

if __name__ == "__main__":
    main()