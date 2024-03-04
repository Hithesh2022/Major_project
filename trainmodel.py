import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn import metrics
import missingno as mn # for missing values visualization
from wordcloud import WordCloud as wc # for most highlighted words visualization
from wordcloud import STOPWORDS as sw # this will help ignoring english stop words in string value
from sklearn.preprocessing import StandardScaler # for stardardizing the data to the normal scale
from sklearn.model_selection import train_test_split # for splitting data into train and test
from sklearn.tree import DecisionTreeClassifier # Decision Tree model classifier
from sklearn.ensemble import RandomForestClassifier # RandomForest model classification
from sklearn.linear_model import LogisticRegression # Logistic Regression
from sklearn.metrics import classification_report,confusion_matrix


import warnings
warnings.filterwarnings("ignore")

col_names = np.array(["duration","protocol_type","service","flag","src_bytes",
    "dst_bytes","land","wrong_fragment","urgent","hot","num_failed_logins",
    "logged_in","num_compromised","root_shell","su_attempted","num_root",
    "num_file_creations","num_shells","num_access_files","num_outbound_cmds",
    "is_host_login","is_guest_login","count","srv_count","serror_rate",
    "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
    "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate", "class", 'difficulty level']) 

train_df = pd.read_csv(r"C:\Users\hith6\OneDrive\Desktop\Major_project\Kddcup99_csv.csv", names = col_names)
train_df

train_df.info()
train_df.isnull().sum()

mn.bar(train_df, color = 'yellowgreen', figsize = (20,15))
test_df = pd.read_csv("KDDTest+.txt", names = col_names)
test_df
test_df.info()
test_df.isnull().sum()
mn.bar(test_df, color = 'lightskyblue', figsize = (20,15)) # no missing data found in test data also
train_df['class'].unique()
train_df['difficulty level'].unique()
classLabel_counts = train_df.groupby(['class']).size()
classLabel_counts
per_classLabels = classLabel_counts/train_df.shape[0]*100
per_classLabels
fig = plt.figure(figsize = (20,10))
r_ = [round(each, 2) for each in per_classLabels.values]
ax = fig.add_subplot(111)
ax.bar(per_classLabels.index, per_classLabels.values, color = ["mediumaquamarine", 'c', 'darkblue', 'tomato', 'navy'], edgecolor = 'black')
ax.set_xticklabels(per_classLabels.index, rotation = 45)
ax.set_xlabel("Feature Name", fontsize = 20)
ax.set_ylabel("Count", fontsize = 20)
ax.set_title("Feature 'Class' label counts", fontsize = 20)

for i in range(len(per_classLabels.values)):
    plt.annotate(str(r_[i]), xy=(per_classLabels.index[i],r_[i]+1), ha='center', va='bottom')
group_data = train_df.groupby('class').size()
plt.figure(figsize = (15,12))
group_data.plot(kind='pie')
plt.title("Different types of Classes in data")
plt.ylabel("")
plt.show()
group_data = train_df.groupby('difficulty level').size()
plt.figure(figsize = (16,16))
group_data.plot(kind='pie')
plt.title("Different types of Difficulty Levels in data")
plt.ylabel("")
plt.show()
train_df
Dos = ['land','neptune','smurf','pod','back','teardrop']
Probe = ['portsweep','ipsweep','satan','nmap']
U2R = ['buffer_overflow','loadmodule','perl','rootkit']

def encode_attack(vec):
    if vec in Dos:
        return "Dos"
    elif vec in Probe:
        return "Probe";
    elif vec in U2R:
        return "U2R"
    elif vec == "normal":
        return "normal"
    else:
        return "R2L"
train_df['attack_type'] = train_df['class'].apply(encode_attack)
train_df.iloc[:10, -5:]
train_df.groupby('attack_type').size()
percent_data = (train_df.groupby('attack_type').size())/train_df.shape[0] * 100
percent_data
fig = plt.figure(figsize = (10,8))
r_ = [round(each, 2) for each in percent_data.values]
ax = fig.add_subplot(111)
ax.bar(percent_data.index, percent_data.values, color = ['darkred', 'teal', 'gold', 'lightseagreen', "mediumaquamarine"], edgecolor = 'black')
ax.set_xticklabels(percent_data.index, rotation = 45)
ax.set_xlabel("Attack type", fontsize = 20)
ax.set_ylabel("Count", fontsize = 20)
ax.set_title("Attacks type data counts", fontsize = 20)

for i in range(len(percent_data.values)):
    plt.annotate(str(r_[i]), xy=(percent_data.index[i],r_[i]+1), ha='center', va='bottom')
group_data = train_df.groupby('attack_type').size()
plt.figure(figsize = (10,8))
group_data.plot(kind='pie')
plt.title("Different types of attack types in data")
plt.ylabel("")
plt.show()
plt.subplots(figsize=(10,8))
train_df['protocol_type'].value_counts(normalize = True)
train_df['protocol_type'].value_counts(dropna = False).plot.bar(color=['teal', 'lightseagreen', 'gold', 'olive'])
plt.show()
plt.subplots(figsize=(25,16))
train_df['service'].value_counts(normalize = True)
train_df['service'].value_counts(dropna = False).plot.bar(color=['teal', 'lightseagreen', 'gold', 'olive'])
plt.show()
plt.subplots(figsize=(10,8))
train_df['flag'].value_counts(normalize = True)
train_df['flag'].value_counts(dropna = False).plot.bar(color=['teal', 'lightseagreen', 'gold', 'olive'])
plt.show()
stop_words = set(sw)

word_cloud = wc(stopwords = stop_words).generate(str(train_df['flag']))

plt.rcParams['figure.figsize'] = (15, 8)
plt.rcParams['lines.color'] = 'gold'
print(word_cloud)
plt.imshow(word_cloud)
plt.title('Most Highlighted Flags', fontsize = 25)
plt.axis("off")
plt.figure(figsize=(30, 40))
sns.heatmap(train_df.corr(), annot=True, cmap="tab20", annot_kws={"size":10})
train_df
numerical_cols = [one for each,one in zip(list(train_df.dtypes),train_df.dtypes.index)  if each == 'int64' or each == 'float64']
numerical_cols
fig = plt.figure(figsize = (10,8))
avg_pro = pd.crosstab(train_df['flag'], train_df['attack_type'])
avg_pro.div(avg_pro.sum(1).astype(float), axis = 0).plot(kind = 'bar', stacked = True, color = ['indigo', 'gold', 'teal', 'olive', 'slategrey'])

plt.title('Dependency of "flags" in attack type', fontsize = 20)
plt.xlabel('Flags', fontsize = 20)
plt.legend()
plt.show()
fig = plt.figure(figsize = (10,8))
avg_pro = pd.crosstab(train_df['protocol_type'], train_df['attack_type'])
avg_pro.div(avg_pro.sum(1).astype(float), axis = 0).plot(kind = 'bar', stacked = True, color = ['indigo', 'gold', 'teal', 'olive', 'slategrey'])

plt.title('Dependency of "Protocols" in Attack types', fontsize = 20)
plt.xlabel('Protocol Types', fontsize = 20)
plt.legend()
plt.show()
fig = plt.figure(figsize = (10,8))
avg_pro = pd.crosstab(train_df['service'], train_df['attack_type'])
avg_pro.div(avg_pro.sum(1).astype(float), axis = 0).plot(kind = 'bar', stacked = True, color = ['indigo', 'gold', 'teal', 'olive', "slategrey"])

plt.title('Dependency of "Services" in Attack types', fontsize = 20)
plt.xlabel('Service Types', fontsize = 20)
plt.legend()
plt.show()
fig = plt.figure(figsize = (10,8))
avg_pro = pd.crosstab(train_df['difficulty level'], train_df['attack_type'])
avg_pro.div(avg_pro.sum(1).astype(float), axis = 0).plot(kind = 'bar', stacked = True, color = ['indigo', 'gold', 'teal', 'olive', "slategrey"])

plt.title('Dependency of "Difficulty Levels" in Attack types', fontsize = 20)
plt.xlabel('Difficulty Levels', fontsize = 20)
plt.legend()
plt.show()
train_df.head(10)
def attack_encode(value):
    if value == 'normal':
        return 0;
    elif value == "Dos":
        return 1;
    elif value == 'Probe':
        return 2;
    elif value == 'R2L':
        return 3;
    else:
        return 4;
train_df['intrusion_code'] = train_df['attack_type'].apply(attack_encode)
train_df.iloc[:10, -5:]
train_df[train_df['intrusion_code'] == 2].iloc[:10, -5:].head()
train_df[train_df['intrusion_code'] == 3].iloc[:10, -5:].head()
train_df[train_df['intrusion_code'] == 4].iloc[:10, -5:].head()
test_df
test_df['attack_type'] = test_df['class'].apply(encode_attack)
test_df.iloc[:20, -10:]
test_df['intrusion_code'] = test_df['attack_type'].apply(attack_encode)
test_df.iloc[:10, -5:]
train_df.head(10)
test_df.head(10)
train_df = train_df.drop(columns = ['class','difficulty level', 'attack_type'])
test_df = test_df.drop(columns = ['class', 'difficulty level','attack_type'])
train_df.head()
test_df.head()
train_df.corr()['intrusion_code'].sort_values(ascending = False)
# Select only categorical variables
category_df = train_df.select_dtypes('object')

dummy_df = pd.get_dummies(category_df)

dummy_df['intrusion_code'] = train_df['intrusion_code']

dummy_df.head()
dummy_df.corr()['intrusion_code'].sort_values(ascending=False)


train_df.columns
train_df = train_df.drop(columns=['num_outbound_cmds', 'srv_count', 'dst_bytes', 'src_bytes', 
                                  'land', 'is_host_login', 'urgent', 'num_failed_logins', 'num_shells'])

test_df = test_df.drop(columns=['num_outbound_cmds', 'srv_count', 'dst_bytes', 'src_bytes', 
                                  'land', 'is_host_login', 'urgent', 'num_failed_logins', 'num_shells'
                                 ])

train_df.tail(10)
test_df.head(10)
train_df.corr()['intrusion_code'].sort_values(ascending = False)
train_df_new = pd.get_dummies(train_df)
test_df_new = pd.get_dummies(test_df)
print (train_df_new.shape)
print (test_df_new.shape)
set(train_df_new.columns).difference(set(test_df_new))
train_df_new
highly_correlated = train_df_new.corr().abs()['intrusion_code'].sort_values(ascending=False)
highly_correlated[:30]
list(highly_correlated[:30].index)
train_df_new = train_df_new[list(highly_correlated[:30].index)]
test_df_new = train_df_new[list(highly_correlated[:30].index)]
corr_df = train_df_new.corr()[train_df_new.corr().index]
fig, ax = plt.subplots(figsize=(20,20))
sns.heatmap(corr_df, cmap='viridis', annot=True, annot_kws={"size": 11})
plt.show()
train_df_new.head(10)
test_df_new.head(10)
train_df_new.shape
test_df_new.shape
X = train_df_new.drop(columns = 'intrusion_code')
y = train_df_new['intrusion_code']
X.shape
scaler = StandardScaler().fit(X)
X = scaler.transform(X)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.5, random_state=13)
# Decision Tree Model

dtree = DecisionTreeClassifier(criterion='entropy',max_depth=10, min_samples_split = 2)
dtree.fit(X_train,y_train)
#KNN Model
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import VotingClassifier
import joblib
knn = KNeighborsClassifier(n_neighbors=5)
knn.fit(X_train,y_train)
ensemble_clf = VotingClassifier(estimators=[('decision_tree', dtree), ('knn', knn)], voting='hard')

# Train the ensemble classifier
ensemble_clf.fit(X_train, y_train)

# Store the trained model using joblib.dump
joblib.dump(ensemble_clf, 'ensemble_model.joblib')




































