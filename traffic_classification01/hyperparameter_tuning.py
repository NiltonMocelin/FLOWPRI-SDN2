



from classificadorBatch import ClassificadorBatch
from classificadorStreaming import ClassificadorStreaming
from sklearn.metrics import accuracy_score, confusion_matrix, precision_score, recall_score,f1_score, ConfusionMatrixDisplay

from sklearn.model_selection import train_test_split

import pandas as pd
import os
import argparse
import time


filename = "../extrair_features/nooutliers_2uniq_newab_10pkts_2s.csv"

#     chunk = chunk.drop(columns=['id','app_class','service_class', 'qos'])
data = pd.read_csv(filename, sep=',', encoding="UTF-8")

print(data.iloc[0])
print(data.columns)

# print(data["app_class"].unique())


df = data.loc[data['service_class']=='be']

print(df['app_class'].unique())

exit(0)



print(df['app_class'].value_counts())

exit(0)

classes_df = data["app_class"].to_list()
data = data.drop(columns=['id','app_class', 'service_class','qos_class'])

#####
print("Fazendo hyper parameter tuning")
X_train, X_test, y_train, y_test = train_test_split(data, classes_df,test_size=0.2, random_state=42)# Treinando modelo

rfc = ClassificadorBatch(nome_classificador="RandomForest", tcp_only=True, two_ways=True)
dtc = ClassificadorBatch(nome_classificador="DecisionTree", tcp_only=False, two_ways=False)
xgbc = ClassificadorBatch(nome_classificador="XGBoost", tcp_only=False, two_ways=False)
svmc = ClassificadorBatch(nome_classificador="SVM", tcp_only=False, two_ways=False)


parameters_rfc = rfc.hyperparameter_tune(X_train,y_train)
parameters_dtc = dtc.hyperparameter_tune(X_train,y_train)
parameters_xgbc = xgbc.hyperparameter_tune(X_train,y_train)
parameters_svmc = svmc.hyperparameter_tune(X_train,y_train)


print("RFC best_params: ", parameters_rfc )
print("DTC best_params: ", parameters_dtc )
print("XGBC best_params: ", parameters_xgbc)
print("SVMC best_params: ", parameters_svmc)

exit(0)