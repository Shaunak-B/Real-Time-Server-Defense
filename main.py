import boto3
from predict import *

import os
import pandas as pd
import numpy as np
#import matplotlib.pyplot as plt
import seaborn as sns
import keras
from keras.models import load_model
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import accuracy_score
from tensorflow.keras.utils import to_categorical

from io import StringIO  

s3client = boto3.client(
    's3',
    region_name='us-east-1'
)

bucket_name = 'real-server-defense'
file_to_read = 'corrected'

#Create a file object using the bucket and object key. 
fileobj = s3client.get_object(
    Bucket=bucket_name,
    Key=file_to_read
    )

# open the file object and read it into the variable filedata. 
filedata = fileobj['Body'].read()

# file data will be a binary stream.  We have to decode it 
contents = filedata.decode('utf-8') 

# NEED TO PASS 'line' TO MODEL
cols="""duration,
    protocol_type,
    service,
    flag,
    src_bytes,
    dst_bytes,
    land,
    wrong_fragment,
    urgent,
    hot,
    num_failed_logins,
    logged_in,
    num_compromised,
    root_shell,
    su_attempted,
    num_root,
    num_file_creations,
    num_shells,
    num_access_files,
    num_outbound_cmds,
    is_host_login,
    is_guest_login,
    count,
    srv_count,
    serror_rate,
    srv_serror_rate,
    rerror_rate,
    srv_rerror_rate,
    same_srv_rate,
    diff_srv_rate,
    srv_diff_host_rate,
    dst_host_count,
    dst_host_srv_count,
    dst_host_same_srv_rate,
    dst_host_diff_srv_rate,
    dst_host_same_src_port_rate,
    dst_host_srv_diff_host_rate,
    dst_host_serror_rate,
    dst_host_srv_serror_rate,
    dst_host_rerror_rate,
    dst_host_srv_rerror_rate"""

columns=[]
for c in cols.split(','):
    if(c.strip()):
        columns.append(c.strip())

columns.append('target')
attacks_types = {
    'normal.': 'normal',
'back.': 'dos',
'buffer_overflow.': 'u2r',
'ftp_write.': 'r2l',
'guess_passwd.': 'r2l',
'imap.': 'r2l',
'ipsweep.': 'probe',
'land.': 'dos',
'loadmodule.': 'u2r',
'multihop.': 'r2l',
'neptune.': 'dos',
'nmap.': 'probe',
'perl.': 'u2r',
'phf.': 'r2l',
'pod.': 'dos',
'portsweep.': 'probe',
'rootkit.': 'u2r',
'satan.': 'probe',
'smurf.': 'dos',
'spy.': 'r2l',
'teardrop.': 'dos',
'warezclient.': 'r2l',
'warezmaster.': 'r2l',
}
attacks_types
'''
path = "corrected"
df = pd.read_csv(path,names=columns)
'''
data = StringIO(contents)
df = pd.read_csv(data, names=columns, sep=",")
df.shape
df = df[df.target.isin(list(attacks_types.keys()))]
df['attack_type'] = df.target.apply(lambda r:attacks_types[r[:]])
df.attack_type.unique()
df.isnull().sum()
num_cols = df._get_numeric_data().columns

cate_cols = list(set(df.columns)-set(num_cols))
cate_cols.remove('target')
cate_cols.remove('attack_type')

cate_cols

df = df.dropna('columns')# drop columns with NaN

df = df[[col for col in df if df[col].nunique() > 1]]

df.drop('num_root',axis = 1,inplace = True)
df.drop('srv_serror_rate',axis = 1,inplace = True)
df.drop('srv_rerror_rate',axis = 1, inplace=True)
df.drop('dst_host_srv_serror_rate',axis = 1, inplace=True)
df.drop('dst_host_serror_rate',axis = 1, inplace=True)
df.drop('dst_host_rerror_rate',axis = 1, inplace=True)
df.drop('dst_host_srv_rerror_rate',axis = 1, inplace=True)
df.drop('dst_host_same_srv_rate',axis = 1, inplace=True)


df['protocol_type'].value_counts()



pmap = {'icmp':0,'tcp':1,'udp':2}
df['protocol_type'] = df['protocol_type'].map(pmap)

fmap = {'SF':0,'S0':1,'REJ':2,'RSTR':3,'RSTO':4,'SH':5 ,'S1':6 ,'S2':7,'RSTOS0':8,'S3':9 ,'OTH':10}
df['flag'] = df['flag'].map(fmap)

attackmap = {'dos':0, 'normal':1, 'probe':2, 'r2l':3, 'u2r':4}
df['attack_type'] = df['attack_type'].map(attackmap)


df.drop('service',axis = 1,inplace= True)
df.drop('target', axis = 1, inplace=True)
df.drop('attack_type', axis = 1, inplace=True)

df.dtypes

sc = MinMaxScaler()

x_test = sc.fit_transform(df)

result_file = open("result.txt", "w")
for i in range(x_test.shape[0]):
    result = predictResult(x_test[i])

    reverse_attackmap = {k:v for v,k in attackmap.items()}
    results = pd.DataFrame(result)
    results = results[0].map(reverse_attackmap)

    # need to send this to frontend in this for loop
    result_file.write(results[0])
