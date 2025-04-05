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
st.write("App version: 2.0")
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
        # Check for existing token
        accounts = self.app.get_accounts()
        if accounts:
            result = self.app.acquire_token_silent(SCOPES, account=accounts[0])
            if result:
                return result['access_token']

        # Initialize device flow
        flow = self.app.initiate_device_flow(scopes=SCOPES)
        if 'user_code' not in flow:
            st.error('Failed to create device flow')
            return None

        placeholder = st.empty()

        try:
            # Try to use Selenium for automated browser handling
            from selenium import webdriver
            from selenium.webdriver.common.by import By
            from selenium.webdriver.support.ui import WebDriverWait
            from selenium.webdriver.support import expected_conditions as EC

            with placeholder.container():
                st.markdown("### Microsoft Authentication")
                st.info("Automating browser authentication...")

            # Initialize browser
            options = webdriver.ChromeOptions()
            options.add_argument('--start-maximized')
            driver = webdriver.Chrome(options=options)

            # Open Microsoft login page
            driver.get(flow['verification_uri'])

            # Wait for code input field and enter code
            code_input = WebDriverWait(driver, 10).until(
                EC.presence_of_element_located((By.NAME, "code"))
            )
            code_input.send_keys(flow['user_code'])

            # Wait for authentication to complete
            with placeholder.container():
                with st.spinner("Completing authentication in browser..."):
                    result = self.app.acquire_token_by_device_flow(flow)

            # Close browser
            driver.quit()

        except Exception as selenium_error:
            # Fall back to manual browser handling if Selenium fails
            st.warning("Automated browser handling failed, falling back to manual mode...")
            
            with placeholder.container():
                st.markdown("### Microsoft Authentication Required")
                st.info("Opening browser for authentication...")
                code_col, text_col = st.columns([1, 2])
                with code_col:
                    st.code(flow['user_code'], language=None)
                with text_col:
                    st.write("👆 Code has been copied to clipboard. Paste it in the browser window.")

            # Copy code to clipboard
            js_code = f"""
                <script>
                    navigator.clipboard.writeText('{flow['user_code']}');
                </script>
            """
            st.components.v1.html(js_code, height=0)

            # Open browser manually
            webbrowser.open_new(flow['verification_uri'])

            # Wait for authentication
            with placeholder.container():
                with st.spinner("Waiting for authentication..."):
                    result = self.app.acquire_token_by_device_flow(flow)

        # Clear placeholder
        placeholder.empty()

        if 'access_token' in result:
            temp_placeholder = st.empty()
            temp_placeholder.success("✅ Authentication successful!")
            time.sleep(2)
            temp_placeholder.empty()
            return result['access_token']

        st.error("❌ Authentication failed. Please try again.")
        return None

    except Exception as e:
        st.error(f"Authentication error: {str(e)}")
        st.code(traceback.format_exc())
        return None

    except Exception as e:
        st.error(f"Authentication error: {str(e)}")
        st.code(traceback.format_exc())
        return None
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

# Add this at the top with your other constants
LICENSE_MAPPING = {
    # Enterprise Plans
    '18181a46-0d4e-45cd-891e-60aabd171b4e': 'Office 365 E1',
    '6fd2c87f-b296-42f0-b197-1e91e994b900': 'Office 365 E3',
    'c7df2760-2c81-4ef7-b578-5b5392b571df': 'Office 365 E5',
    
    # Microsoft 365 Enterprise Plans
    '05e9a617-0261-4cee-bb44-138d3ef5d965': 'Microsoft 365 E3',
    '06ebc4ee-1bb5-47dd-8120-11324bc54e06': 'Microsoft 365 E5',
    
    # Business Plans
    'a403ebcc-fae0-4ca2-8c8c-7a907fd6c235': 'Microsoft 365 Business Basic',
    'f245ecc8-75af-4f8e-b61f-27d8114de5f3': 'Microsoft 365 Business Standard',
    '05c9a76e-fafd-4d67-b63e-36addf2592d0': 'Microsoft 365 Business Premium',
    
    # Exchange Online Plans
    '4b9405b0-7788-4568-add1-99614e613b69': 'Exchange Online (Plan 1)',
    '19ec0d23-8335-4cbd-94ac-6050e30712fa': 'Exchange Online (Plan 2)',
    
    # Other Common Plans
    '3b555118-da6a-4418-894f-7df1e2096870': 'Microsoft 365 Business Basic',
    'f8a1db68-be16-40ed-86d5-cb42ce701560': 'Power BI Pro',
    'c5928f49-12ba-48f7-ada3-0d743a3601d5': 'Microsoft Teams Exploratory'
}

def get_mfa_status(token, user_limit=None):
    try:
        headers = {'Authorization': f'Bearer {token}'}
        
        # Get users with expanded license details
        base_url = 'https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,createdDateTime,signInActivity,assignedLicenses'
        if user_limit:
            base_url += f'&$top={user_limit}'
        
        users_response = requests.get(base_url, headers=headers)
        
        if users_response.status_code != 200:
            st.error(f"Users API Error: {users_response.status_code} - {users_response.text}")
            return None
        
        users_data = users_response.json().get('value', [])
        st.info(f"Fetched {len(users_data)} users")
        mfa_data = []
        
        progress_bar = st.progress(0)
        for index, user in enumerate(users_data):
            try:
                progress = (index + 1) / len(users_data)
                progress_bar.progress(progress)
                
                # Get detailed license information
                license_response = requests.get(
                    f'https://graph.microsoft.com/v1.0/users/{user["id"]}/licenseDetails',
                    headers=headers
                )
                
                # Get authentication methods
                auth_methods_response = requests.get(
                    f'https://graph.microsoft.com/v1.0/users/{user["id"]}/authentication/methods',
                    headers=headers
                )
                
                # Process license information
                licenses = []
                if license_response.status_code == 200:
                    license_details = license_response.json().get('value', [])
                    for license in license_details:
                        sku_id = license.get('skuId', '')
                        license_name = LICENSE_MAPPING.get(sku_id, f'Unknown License ({sku_id})')
                        licenses.append(license_name)
                
                # Process MFA status
                mfa_status = "Disabled"
                auth_methods = []
                if auth_methods_response.status_code == 200:
                    methods = auth_methods_response.json().get('value', [])
                    auth_methods = [m.get('methodType', '') for m in methods]
                    if any(method != 'password' for method in auth_methods):
                        mfa_status = "Enabled"
                
                mfa_data.append({
                    'DisplayName': user.get('displayName'),
                    'UserPrincipalName': user.get('userPrincipalName'),
                    'Licenses': ', '.join(licenses) if licenses else 'No License',
                    'MFAStatus': mfa_status,
                    'AuthMethods': ', '.join(auth_methods) if auth_methods else 'None',
                    'CreationDate': user.get('createdDateTime'),
                    'LastInteractiveSignIn': user.get('signInActivity', {}).get('lastSignInDateTime'),
                    'LastNonInteractiveSignIn': user.get('signInActivity', {}).get('lastNonInteractiveSignInDateTime')
                })
                
            except Exception as e:
                st.error(f"Error processing user {user.get('userPrincipalName')}: {str(e)}")
                continue
        
        progress_bar.empty()
        df = pd.DataFrame(mfa_data)
        
        # Add license summary
        st.write("\n### License Distribution")
        license_counts = df['Licenses'].value_counts()
        st.write(license_counts)
        
        # Add MFA by license type visualization
        st.write("\n### MFA Status by License Type")
        pivot_table = pd.crosstab(df['Licenses'], df['MFAStatus'])
        st.bar_chart(pivot_table)
        
        # Detailed data table
        st.write("\n### Detailed User Data")
        
        # Add column configuration for better display
        column_config = {
            'DisplayName': st.column_config.TextColumn('Name'),
            'UserPrincipalName': st.column_config.TextColumn('Email'),
            'Licenses': st.column_config.TextColumn('Assigned Licenses'),
            'MFAStatus': st.column_config.TextColumn('MFA Status'),
            'AuthMethods': st.column_config.TextColumn('Authentication Methods'),
            'CreationDate': st.column_config.DatetimeColumn('Created'),
            'LastInteractiveSignIn': st.column_config.DatetimeColumn('Last Interactive Sign-in'),
            'LastNonInteractiveSignIn': st.column_config.DatetimeColumn('Last Non-interactive Sign-in')
        }
        
        st.dataframe(
            df,
            column_config=column_config,
            hide_index=True
        )
        
        return df
        
    except Exception as e:
        st.error(f"MFA status error: {str(e)}")
        st.code(traceback.format_exc())
        return None
    try:
        headers = {'Authorization': f'Bearer {token}'}
        
        # Modify the API call to include top parameter if user_limit is specified
        base_url = 'https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,createdDateTime,signInActivity'
        if user_limit:
            base_url += f'&$top={user_limit}'
        
        users_response = requests.get(base_url, headers=headers)
        
        if users_response.status_code != 200:
            st.error(f"Users API Error: {users_response.status_code} - {users_response.text}")
            return None
        
        users_data = users_response.json().get('value', [])
        st.info(f"Fetched {len(users_data)} users")
        mfa_data = []
        
        # Add a progress bar
        progress_bar = st.progress(0)
        for index, user in enumerate(users_data):
            try:
                # Update progress bar
                progress = (index + 1) / len(users_data)
                progress_bar.progress(progress)
                
                # Get authentication methods
                auth_methods_response = requests.get(
                    f'https://graph.microsoft.com/v1.0/users/{user["id"]}/authentication/methods',
                    headers=headers
                )
                
                # Get user's license information
                license_response = requests.get(
                    f'https://graph.microsoft.com/v1.0/users/{user["id"]}/licenseDetails',
                    headers=headers
                )
                
                mfa_status = "Disabled"
                auth_methods = []
                license_info = "No License"
                
                if auth_methods_response.status_code == 200:
                    methods = auth_methods_response.json().get('value', [])
                    auth_methods = [m.get('methodType', '') for m in methods]
                    if any(method != 'password' for method in auth_methods):
                        mfa_status = "Enabled"
                
                # Process license information
                if license_response.status_code == 200:
                    licenses = license_response.json().get('value', [])
                    license_names = []
                    for license in licenses:
                        sku_id = license.get('skuId', '')
                        # Map common Microsoft 365 SKU IDs to readable names
                        license_map = {
                            '18181a46-0d4e-45cd-891e-60aabd171b4e': 'E1',
                            '6fd2c87f-b296-42f0-b197-1e91e994b900': 'E3',
                            'c7df2760-2c81-4ef7-b578-5b5392b571df': 'E5',
                            '05e9a617-0261-4cee-bb44-138d3ef5d965': 'Microsoft 365 E3',
                            '06ebc4ee-1bb5-47dd-8120-11324bc54e06': 'Microsoft 365 E5',
                            'a403ebcc-fae0-4ca2-8c8c-7a907fd6c235': 'Microsoft 365 Business Basic',
                            'f245ecc8-75af-4f8e-b61f-27d8114de5f3': 'Microsoft 365 Business Standard',
                            '05c9a76e-fafd-4d67-b63e-36addf2592d0': 'Microsoft 365 Business Premium'
                            # Add more SKU IDs as needed
                        }
                        license_name = license_map.get(sku_id, 'Unknown License')
                        license_names.append(license_name)
                    
                    license_info = ', '.join(license_names) if license_names else 'No License'
                
                mfa_data.append({
                    'DisplayName': user.get('displayName'),
                    'UserPrincipalName': user.get('userPrincipalName'),
                    'License': license_info,
                    'MFAStatus': mfa_status,
                    'AuthMethods': ', '.join(auth_methods) if auth_methods else 'None',
                    'CreationDate': user.get('createdDateTime'),
                    'LastInteractiveSignIn': user.get('signInActivity', {}).get('lastSignInDateTime'),
                    'LastNonInteractiveSignIn': user.get('signInActivity', {}).get('lastNonInteractiveSignInDateTime')
                })
            except Exception as e:
                st.error(f"Error processing user {user.get('userPrincipalName')}: {str(e)}")
                continue
            
        progress_bar.empty()
        return pd.DataFrame(mfa_data)
    except Exception as e:
        st.error(f"MFA status error: {str(e)}")
        st.code(traceback.format_exc())
        return None
    try:
        headers = {'Authorization': f'Bearer {token}'}
        
        # Modify the API call to include top parameter if user_limit is specified
        base_url = 'https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,createdDateTime,signInActivity'
        if user_limit:
            base_url += f'&$top={user_limit}'
        
        users_response = requests.get(base_url, headers=headers)
        
        if users_response.status_code != 200:
            st.error(f"Users API Error: {users_response.status_code} - {users_response.text}")
            return None
        
        users_data = users_response.json().get('value', [])
        st.info(f"Fetched {len(users_data)} users")  # Add info message
        mfa_data = []
        
        # Add a progress bar
        progress_bar = st.progress(0)
        for index, user in enumerate(users_data):
            try:
                # Update progress bar
                progress = (index + 1) / len(users_data)
                progress_bar.progress(progress)
                
                auth_methods_response = requests.get(
                    f'https://graph.microsoft.com/v1.0/users/{user["id"]}/authentication/methods',
                    headers=headers
                )
                
                mfa_status = "Disabled"
                auth_methods = []
                
                if auth_methods_response.status_code == 200:
                    methods = auth_methods_response.json().get('value', [])
                    auth_methods = [m.get('methodType', '') for m in methods]
                    if any(method != 'password' for method in auth_methods):
                        mfa_status = "Enabled"
                
                mfa_data.append({
                    'DisplayName': user.get('displayName'),
                    'UserPrincipalName': user.get('userPrincipalName'),
                    'MFAStatus': mfa_status,
                    'AuthMethods': ', '.join(auth_methods) if auth_methods else 'None',
                    'CreationDate': user.get('createdDateTime'),
                    'LastInteractiveSignIn': user.get('signInActivity', {}).get('lastSignInDateTime'),
                    'LastNonInteractiveSignIn': user.get('signInActivity', {}).get('lastNonInteractiveSignInDateTime')
                })
            except Exception as e:
                st.error(f"Error processing user {user.get('userPrincipalName')}: {str(e)}")
                continue
            
        progress_bar.empty()  # Remove progress bar when done
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
    
    # Add number input for user limit
    user_limit = st.number_input(
        "Number of users to fetch (0 for all users)",
        min_value=0,
        max_value=999,
        value=10,  # Default value
        step=1,
        help="Set to 0 to fetch all users, or specify a number to limit the results"
    )
    
    if st.button("Refresh MFA Status"):
        with st.spinner("Fetching MFA status..."):
            # Pass user_limit to get_mfa_status
            limit = user_limit if user_limit > 0 else None
            df = get_mfa_status(st.session_state.token, limit)
            if df is not None:
                st.session_state.mfa_data = df
            else:
                st.error("Failed to fetch MFA status")
                return

    # Add logout button to sidebar
    if st.sidebar.button("Logout"):
        for key in ['token', 'user_info']:
            st.session_state.pop(key, None)
        st.experimental_rerun()
        return
    
    st.markdown("---")
if 'mfa_data' in st.session_state:
    df = st.session_state.mfa_data
    
    # Show total number of users
    st.write(f"Total users: {len(df)}")
    
    # Create columns for summary stats
    col1, col2 = st.columns(2)
    
    with col1:
        # MFA Status summary
        mfa_summary = df['MFAStatus'].value_counts()
        st.write("### MFA Status Summary:")
        st.write(f"- Enabled: {mfa_summary.get('Enabled', 0)}")
        st.write(f"- Disabled: {mfa_summary.get('Disabled', 0)}")
        
        # Calculate percentages
        total_users = len(df)
        enabled_percent = (mfa_summary.get('Enabled', 0) / total_users * 100) if total_users > 0 else 0
        st.write(f"- MFA Adoption Rate: {enabled_percent:.1f}%")

    with col2:
        # License summary
        st.write("### License Summary:")
        # Split the licenses string and count unique licenses
        license_counts = {}
        for licenses in df['Licenses'].str.split(', '):
            if licenses:
                for license in licenses:
                    license_counts[license] = license_counts.get(license, 0) + 1
        
        # Display license counts
        for license_type, count in sorted(license_counts.items()):
            if license_type != 'No License':
                st.write(f"- {license_type}: {count}")
        
        # Show users with no license separately
        no_license_count = license_counts.get('No License', 0)
        if no_license_count > 0:
            st.write(f"- No License: {no_license_count}")

    # Filters
    st.sidebar.title("Filters")
    
    # MFA Status filter
    mfa_status = st.sidebar.multiselect(
        "MFA Status",
        options=df['MFAStatus'].unique(),
        default=df['MFAStatus'].unique()
    )
    
    # Enhanced License filter
    # Get unique licenses from the comma-separated lists
    all_licenses = set()
    for licenses in df['Licenses'].str.split(', '):
        if licenses:
            all_licenses.update(licenses)
    
    license_types = st.sidebar.multiselect(
        "License Types",
        options=sorted(list(all_licenses)),
        default=sorted(list(all_licenses))
    )
    
    # Apply filters
    # Filter by MFA Status
    df_filtered = df[df['MFAStatus'].isin(mfa_status)]
    
    # Filter by License (check if any selected license is in the user's licenses)
    if license_types:
        df_filtered = df_filtered[
            df_filtered['Licenses'].apply(
                lambda x: any(license in x.split(', ') for license in license_types)
            )
        ]
    
    # Search filter
    search = st.text_input("Search by name or email")
    if search:
        mask = df_filtered.apply(
            lambda x: x.astype(str).str.contains(search, case=False)
        ).any(axis=1)
        df_filtered = df_filtered[mask]
    
    # Show filtered results summary
    st.write(f"\n### Filtered Results: {len(df_filtered)} users")
    
    # Display the filtered data
    st.dataframe(
        df_filtered,
        column_config={
            'DisplayName': 'Name',
            'UserPrincipalName': 'Email',
            'Licenses': 'Assigned Licenses',
            'MFAStatus': 'MFA Status',
            'AuthMethods': 'Authentication Methods',
            'CreationDate': st.column_config.DatetimeColumn('Created'),
            'LastInteractiveSignIn': st.column_config.DatetimeColumn('Last Sign-in'),
            'LastNonInteractiveSignIn': st.column_config.DatetimeColumn('Last Non-interactive')
        },
        hide_index=True
    )
    
    # Export button
    if st.button("Export to CSV"):
        csv = df_filtered.to_csv(index=False)
        st.download_button(
            label="Download CSV",
            data=csv,
            file_name="mfa_status_export.csv",
            mime="text/csv"
        )
    df = st.session_state.mfa_data
    
    # Show total number of users
    st.write(f"Total users: {len(df)}")
    
    # MFA Status summary
    mfa_summary = df['MFAStatus'].value_counts()
    st.write("MFA Status Summary:")
    st.write(f"- Enabled: {mfa_summary.get('Enabled', 0)}")
    st.write(f"- Disabled: {mfa_summary.get('Disabled', 0)}")
    
    # License summary
    license_summary = df['License'].value_counts()
    st.write("\nLicense Summary:")
    for license_type, count in license_summary.items():
        st.write(f"- {license_type}: {count}")
    
    # Filters
    st.sidebar.title("Filters")
    
    # MFA Status filter
    mfa_status = st.sidebar.multiselect(
        "MFA Status",
        options=df['MFAStatus'].unique(),
        default=df['MFAStatus'].unique()
    )
    
    # License filter
    license_types = st.sidebar.multiselect(
        "License Types",
        options=df['License'].unique(),
        default=df['License'].unique()
    )
    
    # Apply filters
    df = df[
        (df['MFAStatus'].isin(mfa_status)) &
        (df['License'].isin(license_types))
    ]
    
    # Search filter
    search = st.text_input("Search by name or email")
    if search:
        mask = df.apply(lambda x: x.astype(str).str.contains(search, case=False)).any(axis=1)
        df = df[mask]
    
    # Add visualization
    if len(df) > 0:
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("MFA Status by License Type")
            pivot_data = pd.crosstab(df['License'], df['MFAStatus'])
            st.bar_chart(pivot_data)
        
        with col2:
            st.write("License Distribution")
            license_counts = df['License'].value_counts()
            st.pie_chart(license_counts)
    
    st.dataframe(df)
    
    if st.button("Export to CSV"):
        csv = df.to_csv(index=False)
        st.download_button(
            label="Download CSV",
            data=csv,
            file_name="mfa_status_export.csv",
            mime="text/csv"
        )
        df = st.session_state.mfa_data
        
        # Show total number of users
        st.write(f"Total users: {len(df)}")
        
        # MFA Status summary
        mfa_summary = df['MFAStatus'].value_counts()
        st.write("MFA Status Summary:")
        st.write(f"- Enabled: {mfa_summary.get('Enabled', 0)}")
        st.write(f"- Disabled: {mfa_summary.get('Disabled', 0)}")
        
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