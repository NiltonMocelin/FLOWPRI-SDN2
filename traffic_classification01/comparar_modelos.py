

# Roteiro:
# 
#       * remover campos do cabeçalho IP -> pois usaremos pacotes IPv6 para classificação depois
#
#       * sortear a base
#
#       * hyperparameter tuning
#
#       * fazer cv
#       * dividir em 2 partes 4/5 treino 1/5 teste
#
#       * comparar versao tunada e sem tuning --> coletar metricas de resultado e tempo de teste e treino

# RandomForest
# [Inicio] Fine Tuning -> parametros testados (grid_search):  {'n_estimators': [25, 50, 100], 'max_features': ['sqrt', 'log2', None], 'max_depth': [3, 6, 9], 'max_leaf_nodes': [3, 6, 9]}
# [Fim] Os melhores parametros foram:  {'max_depth': 6, 'max_features': 'log2', 'max_leaf_nodes': 6, 'n_estimators': 25}
# DecisionTree
# [Inicio] Fine Tuning -> parametros testados (grid_search):  {'max_depth': [10, 30, None], 'min_samples_split': [2, 5, 10], 'min_samples_leaf': [1, 2, 4]}
# [Fim] Os melhores parametros foram:  {'max_depth': 10, 'min_samples_leaf': 4, 'min_samples_split': 2}
# SVM {'C': 1000, 'gamma': 1, 'kernel': 'rbf'}

## novo: RF  {'max_depth': 6, 'max_features': None, 'max_leaf_nodes': 9, 'n_estimators': 50}
## novo DT {'max_depth': 10, 'min_samples_leaf': 2, 'min_samples_split': 10}

# classificador:  AdaptiveRandomForest
# {'grace_period': 30, 'split_criterion': 'gini'}

# HoeffdingTreeClassifier
# {'grace_period': 30, 'split_criterion': 'gini'}

# campos a serem removidos: 
    # "mean_data_pkt_ref13",
    # "med_data_pkt_ref12",
    # "std_data_pkt_ref16",
    # "min_data_pkt_ref10",
    # "max_data_pkt_ref15",
    # "q1_data_pkt_ref11",
    # "q3_data_pkt_ref14",
    # "mean_data_ip_ref20",
    # "med_data_ip_ref19",
    # "std_data_ip_ref23",
    # "min_data_ip_ref17",
    # "max_data_ip_ref22",
    # "q1_data_ip_ref18",
    # "q3_data_ip_ref21",
    # "mean_header_ip_ref27",
    # "med_header_ip_ref26",
    # "std_header_ip_ref30",
    # "min_header_ip_ref24",
    # "max_header_ip_ref29",
    # "q1_header_ip_ref25",
    # "q3_header_ip_ref28",
    # "ab_mean_data_pkt_156",
    # "ab_med_data_pkt_155",
    # "ab_var_data_pkt_159",
    # "ab_min_data_pkt_153",
    # "ab_max_data_pkt_158",
    # "ab_q1_data_pkt_154",
    # "ab_q3_data_pkt_157",
    # "ab_mean_data_ip_163",
    # "ab_med_data_ip_162",
    # "ab_var_data_ip_166",
    # "ab_min_data_ip_160",
    # "ab_max_data_ip_165",
    # "ab_q1_data_ip_161",
    # "ab_q3_data_ip_164",
    # "ab_mean_header_ip_ref321",
    # "ab_med_header_ip_ref322",
    # "ab_std_header_ip_ref323",
    # "ab_min_header_ip_ref324",
    # "ab_max_header_ip_ref325",
    # "ab_q1_header_ip_ref326",
    # "ab_q3_header_ip_ref327",
    # "ba_mean_data_pkt_177",
    # "ba_med_data_pkt_176",
    # "ba_var_data_pkt_180",
    # "ba_min_data_pkt_174",
    # "ba_max_data_pkt_179",
    # "ba_q1_data_pkt_175",
    # "ba_q3_data_pkt_178",
    # "ba_mean_header_ip_ref191",
    # "ba_med_header_ip_ref190",
    # "ba_std_header_ip_ref194",
    # "ba_min_header_ip_ref188",
    # "ba_max_header_ip_ref193",
    # "ba_q1_header_ip_ref189",
    # "ba_q3_header_ip_ref192",
    # "ba_mean_data_ip_184",
    # "ba_med_data_ip_183",
    # "ba_var_data_ip_187",
    # "ba_min_data_ip_181",
    # "ba_max_data_ip_186",
    # "ba_q1_data_ip_182",
    # "ba_q3_data_ip_185"]




from classificadorBatch import ClassificadorBatch
from classificadorStreaming import ClassificadorStreaming
from sklearn.metrics import accuracy_score, confusion_matrix, precision_score, recall_score,f1_score, ConfusionMatrixDisplay

import statistics

from sklearn.model_selection import train_test_split, KFold, GridSearchCV

import pandas as pd
import os
import argparse
import time
import sys

from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC

import numpy as np
np.float = float
from skmultiflow.trees import HoeffdingTreeClassifier
from skmultiflow.meta import AdaptiveRandomForestClassifier

import xgboost as xgb

def hyperparameter_tune_stream(nomeClassificador, X, Y):

    classes_streaming = {"chat_real":0,
        "video_real":1,
        "video_estatico":2,
        "audio_real":3,
        "audio_estatico":4,
        "game":5,
        "be":6,
        "qos":7,
        0:"chat_real",
        1:"video_real",
        2:"video_estatico",
        3:"audio_real",
        4:"audio_estatico",
        5:"game",
        6:"be",
        7:"qos"}

    classificador = None
    param_grid = {}
    if nomeClassificador == "AdaptiveRandomForest":
        classificador = AdaptiveRandomForestClassifier()
        param_grid = {'grace_period': [30, 50, 100], 'split_criterion': ['gini', 'info_gain'], 'random_state': [42]}
    else:
        classificador = HoeffdingTreeClassifier()
        param_grid ={'grace_period': [30, 10, 100], 'split_criterion': ['gini', 'info_gain'], 'random_state': [42]}
    
    print("[Inicio] Fine Tuning -> parametros testados (grid_search): ", param_grid)
    X_train, X_test, y_train, y_test = train_test_split(X, Y, 
                                   random_state=104,  
                                   test_size=0.25,  
                                   shuffle=True) 
    best_params = {}
    best_precision = 0

    for i in param_grid["grace_period"]:

        for j in param_grid["split_criterion"]:
            y_pred_lista = []
            print("testando ",i," ", j)
            if nomeClassificador == "AdaptiveRandomForest":
                classificador = AdaptiveRandomForestClassifier(grace_period = i, split_criterion=j)
            else:
                classificador = HoeffdingTreeClassifier(grace_period = i, split_criterion=j)

            for x in range(0,len(X_train)):
                X_train_stream = np.array([X_train.iloc[x].values.flatten().tolist()])
                y_train_stream = np.array([classes_streaming[y_train[x]]])

                classificador.partial_fit(X_train_stream, y_train_stream)#, np.array([0,1]), np.array([1]) ) #y_train_stream)

            for x in range(0,len(X_test)):
                X_test_stream = np.array([X_test.iloc[x].values.flatten().tolist()])
                # y_test_stream = y_test[x]

                y_pred = classificador.predict(X_test_stream)

                y_pred_lista.append(classes_streaming[y_pred[0]])
            
            
            # print(classes_streaming[y_pred[0]], " vs ", np.y_test_stream)
            precision = precision_score(y_test, np.array(y_pred_lista),average='macro')

            if precision > best_precision:
                best_precision = precision
                best_params = {"grace_period":i, "split_criterion": j}

            print("precisao atual:", precision, " ;; melhor precisao:", best_precision)
    print("classificador: ", nomeClassificador)
    print(best_params)
    print("Best-precision:")
    print(best_precision)
    return best_params


def hyperparameter_tune_batch(nomeClassificador, X, Y):
    """Realizar grid search"""
    
    classificador = None

    param_grid = {}
    if nomeClassificador == "RandomForest": #https://www.geeksforgeeks.org/random-forest-hyperparameter-tuning-in-python/
        classificador = RandomForestClassifier()
        param_grid = { 
            'n_estimators': [25, 50, 100], 
            'max_features': ['sqrt', 'log2', None], 
            'max_depth': [3, 6, 9], 
            'max_leaf_nodes': [3, 6, 9], 
        } 
    elif nomeClassificador == "DecisionTree": #https://www.geeksforgeeks.org/how-to-tune-a-decision-tree-in-hyperparameter-tuning/
        classificador = DecisionTreeClassifier()
        param_grid = {
        'max_depth': [10, 30, None],
        'min_samples_split': [2, 5, 10],
        'min_samples_leaf': [1, 2, 4]
        }
    # elif self.nomeClassificador == "XGBoost": #https://medium.com/@rithpansanga/optimizing-xgboost-a-guide-to-hyperparameter-tuning-77b6e48e289d
    #     param_grid = {
    #     'max_depth': [3, 5, 7],
    #     'learning_rate': [0.1, 0.01, 0.001],
    #     'subsample': [0.5, 0.7, 1]
    #     }
    #     params = {
    #         "colsample_bytree": uniform(0.7, 0.3),
    #         "gamma": uniform(0, 0.5),
    #         "learning_rate": uniform(0.03, 0.3), # default 0.1 
    #         "max_depth": randint(2, 6), # default 3
    #         "n_estimators": randint(100, 150), # default 100
    #         "subsample": uniform(0.6, 0.4)
    #     }
    #     search = RandomizedSearchCV(self.classificador, param_distributions=params, random_state=42, n_iter=200, cv=3, verbose=1, n_jobs=1, return_train_score=True)
    #     search.fit(X_train, Y_train)
    #     report_best_scores(search.cv_results_, 1)
    #     return search.cv_results_
    #     # param_grid = {    "objective":['multi:softprob', 'binary:logistic'],
    #     # "num_class": [],      
    #     # "max_depth" : [],       
    #     # "learning_rate": [],
    #     # "subsample":[],        
    #     # "colsample_bytree" : [], 
    #     # "n_estimators" : []
    #     # }

  
    elif nomeClassificador == "SVM": #https://www.geeksforgeeks.org/svm-hyperparameter-tuning-using-gridsearchcv-ml/
        classificador = SVC()
        param_grid =    {'C': [0.1, 1, 10, 100, 1000],  
              'gamma': [1, 0.1, 0.01, 0.001, 0.0001], 
              'kernel': ['rbf']}  
    else:
        print("erro nome do classificador não reconhecido!")
        return
    
    print("[Inicio] Fine Tuning -> parametros testados (grid_search): ", param_grid)
    grid_search = GridSearchCV(estimator=classificador, param_grid=param_grid, cv= 5, n_jobs=-1,scoring='accuracy', refit = True, verbose = 3)
    grid_search.fit(X, Y)
    best_params = grid_search.best_params_
    print("[Fim] Os melhores parametros foram: ", best_params)
    classificador = grid_search.best_estimator_
    return classificador


def finetune(phase):
    # usar um arquivo para fine tuning -- ab_10pkts da vida para be vs qos, 50 pkts que é bem menor
    
    filename = "bases/phase2_agregado_ab_tcp_50pkts.csv"

    data = pd.read_csv(filename, sep=',', encoding="UTF-8")

    # pegar apenas  metade da base, metade de cada classe
    # app_type = data["app_class"].to_list()
    # app_class = data["service_class"].to_list()
    # service_class = data["service_class"].to_list()
    classe_list = data["service_class"].to_list()

    if phase == 1:
        for i in range(0, len(classe_list)):
            if classe_list[i] != "be":
                classe_list[i] = "qos"

    colunas_drop = ["service_class", "app_class", "qos_class"]
    
    data = data.drop(columns=colunas_drop , axis=1, errors='ignore')
    data = data.replace(np.nan, 0)
    
    print("RandomForest")
    hyperparameter_tune_batch("RandomForest", data, classe_list)
    print("DecisionTree")
    hyperparameter_tune_batch("DecisionTree", data, classe_list)
    print("SVM")
    hyperparameter_tune_batch("SVM", data, classe_list)

    print("AdaptiveRandomForest")
    hyperparameter_tune_stream("AdaptiveRandomForest", data, classe_list)
    print("HoeffdingTree")
    hyperparameter_tune_stream("HoeffdingTreeClassifier", data, classe_list)

    return

def phase0(filename):

    colunas_drop = ["service_class", "app_class", "qos_class"]

    data = pd.read_csv(filename, sep=',', encoding="UTF-8")


def testar_base(X_test, classes, modelo):
    y_pred= modelo.predict(X_test)
    print(accuracy_score(classes, y_pred))
    print(precision_score(classes, y_pred,average='macro'))
    print(recall_score(classes, y_pred,average='macro'))
    print(f1_score(classes, y_pred,average='macro'))


def phaseX(filename, phase):

    colunas_drop = ["service_class", "app_class", "qos_class"]
    print("classificacao phase ", phase)

    classes_streaming = {"chat_real":0,
        "video_real":1,
        "video_estatico":2,
        "audio_real":3,
        "audio_estatico":4,
        "game":5,
        "be":6,
        "qos":7,
        0:"chat_real",
        1:"video_real",
        2:"video_estatico",
        3:"audio_real",
        4:"audio_estatico",
        5:"game",
        6:"be",
        7:"qos"}

    if True:
        print("classificando :", filename)
        data = pd.read_csv(filename, sep=',', encoding="UTF-8")

        # app_type = data["app_class"].to_list()
        # app_class = data["service_class"].to_list()
        # service_class = data["service_class"].to_list()

        # dt = pd.read_csv(filename, sep=',', encoding="UTF-8")

        classe_list = data["service_class"].to_list()

        if phase == 1:
            for i in range(0, len(classe_list)):
                if classe_list[i] != "be":
                    classe_list[i] = "qos"

        if phase ==3 :
            for i in range(0, len(classe_list)):
                if classe_list[i] == "estatico":
                    classe_list[i] = "video_estatico"
                elif classe_list[i]== "real":
                    classe_list[i] = "video_real"

        kfold = KFold(n_splits=5, shuffle=True, random_state=42)

        data = data.drop(columns=colunas_drop , axis=1, errors='ignore')
        data = data.replace(np.nan, 0)
         
        precision_rfc = []
        precision_dtc = []
        precision_xgbc = []
        precision_svmc = []
        precision_arfc = []
        precision_htc = []

        accuracy_rfc = []
        accuracy_dtc = []
        accuracy_xgbc = []
        accuracy_svmc = []
        accuracy_htc = []
        accuracy_arfc = []

        f1_rfc = []
        f1_dtc = []
        f1_xgbc = []
        f1_svmc = []
        f1_htc = []
        f1_arfc = []
        
        recall_rfc = []
        recall_dtc = []
        recall_xgbc = []
        recall_svmc = []
        recall_htc = []
        recall_arfc = []

        for train_index, test_index in kfold.split(data):   
            print(train_index, test_index)
            
            X_train, X_test = data.iloc[train_index], data.iloc[test_index]
            y_train = []
            y_test = []
            for i in train_index:
                y_train.append(classe_list[i])

            for i in test_index:
                y_test.append(classe_list[i])

            # y_train, y_test = classe_list[train_index], classe_list[test_index]
# max_depth': 10, 'min_samples_leaf': 4, 'min_samples_split': 2
            rfc = RandomForestClassifier(max_depth=6, max_features='log2', max_leaf_nodes=6,n_estimators=25)
            dtc = DecisionTreeClassifier(max_depth=10, min_samples_leaf=4, min_samples_split=2)
            svc = SVC(C=1000, kernel='rbf', gamma=1)
            arfc = AdaptiveRandomForestClassifier(grace_period=100, split_criterion='gini')
            htc = HoeffdingTreeClassifier(grace_period=30, split_criterion='gini')

            xgbc = xgb.XGBClassifier(tree_method="hist", random_state=42)
            

            rfc.fit(X_train,y_train)
            dtc.fit(X_train,y_train)
            svc.fit(X_train,y_train)

            y_pred= rfc.predict(X_test)
            accuracy_rfc.append(accuracy_score(y_test, y_pred))
            precision_rfc.append(precision_score(y_test, y_pred,average='macro'))
            recall_rfc.append(recall_score(y_test, y_pred,average='macro'))
            f1_rfc.append(f1_score(y_test, y_pred,average='macro'))


            if phase == 3:

                print("resultados random forest")

                print(accuracy_rfc)
                print(precision_rfc)
                print(recall_rfc)
                print(f1_rfc)

                data = pd.read_csv("bases/phase2_agregado_ab_10pkts.csv", sep=',', encoding="UTF-8")
                
                nova_data = data.drop(columns=colunas_drop , axis=1, errors='ignore')
                nova_data = nova_data.replace(np.nan, 0)

                as_classes = nova_data["service_classes"].to_list()
                testar_base(nova_data, as_classes, rfc)
                exit(0)

            
            
            # xgbc.fit(X_train,y_train)
            y_train_xgb = []
            y_test_xgb = []
            desconto = 6 if phase==1 else 0
            for i in range(0,len(y_train)):
                y_train_xgb.append(classes_streaming[y_train[i]]-desconto)
            for i in range(0,len(y_test)):
                y_test_xgb.append(classes_streaming[y_test[i]]-desconto)
            
            xgbc.fit(X_train,y_train_xgb)

            y_pred = xgbc.predict(X_test)

            # print(y_pred.tolist())
            accuracy_xgbc.append(accuracy_score(y_test_xgb, y_pred))
            precision_xgbc.append(precision_score(y_test_xgb, y_pred,average='macro'))
            recall_xgbc.append(recall_score(y_test_xgb, y_pred,average='macro'))
            f1_xgbc.append(f1_score(y_test_xgb, y_pred,average='macro'))
            

            for i in train_index:
                X_train_stream = np.array([data.iloc[i].values.flatten().tolist()])
                y_train_stream = np.array([classes_streaming[classe_list[i]]])

                arfc.partial_fit(X_train_stream, y_train_stream)
                htc.partial_fit(X_train_stream, y_train_stream) 

            y_pred_arfc = []
            y_pred_htc = []
            for i in test_index:
                X_test_stream = np.array([data.iloc[i].values.flatten().tolist()])
                # y_test_stream = np.array([classe_list[i]]) 

                y_pred = arfc.predict(X_test_stream)
                y_pred_arfc.append(classes_streaming[y_pred[0]])
            
                y_pred= htc.predict(X_test_stream)
                y_pred_htc.append(classes_streaming[y_pred[0]])

            accuracy_arfc.append(accuracy_score(y_test, np.array(y_pred_arfc)))
            precision_arfc.append(precision_score(y_test, np.array(y_pred_arfc),average='macro'))
            recall_arfc.append(recall_score(y_test, np.array(y_pred_arfc),average='macro'))
            f1_arfc.append(f1_score(y_test, np.array(y_pred_arfc),average='macro'))

            accuracy_htc.append(accuracy_score(y_test, np.array(y_pred_htc)))
            precision_htc.append(precision_score(y_test, np.array(y_pred_htc),average='macro'))
            recall_htc.append(recall_score(y_test, np.array(y_pred_htc),average='macro'))
            f1_htc.append(f1_score(y_test, np.array(y_pred_htc),average='macro'))


            y_pred= dtc.predict(X_test)
            accuracy_dtc.append(accuracy_score(y_test, y_pred))
            precision_dtc.append(precision_score(y_test, y_pred,average='macro'))
            recall_dtc.append(recall_score(y_test, y_pred,average='macro'))
            f1_dtc.append(f1_score(y_test, y_pred,average='macro'))

            y_pred= svc.predict(X_test)
            accuracy_svmc.append(accuracy_score(y_test, y_pred))
            precision_svmc.append(precision_score(y_test, y_pred,average='macro'))
            recall_svmc.append(recall_score(y_test, y_pred,average='macro'))
            f1_svmc.append(f1_score(y_test, y_pred,average='macro'))

        print("resultados ", filename, ' phase: ', phase)

        print("RFC")
        print("accuracy:",statistics.mean(accuracy_rfc))
        print("precision:",statistics.mean(precision_rfc))
        print("recall:",statistics.mean(recall_rfc))
        print("f1:",statistics.mean(f1_rfc))

        print("\nDTC")
        print("accuracy:",statistics.mean(accuracy_dtc))
        print("precision:",statistics.mean(precision_dtc))
        print("recall:",statistics.mean(recall_dtc))
        print("f1:",statistics.mean(f1_dtc))
        
        print("\nSVC")
        print("accuracy:",statistics.mean(accuracy_svmc))
        print("precision:",statistics.mean(precision_svmc))
        print("recall:",statistics.mean(recall_svmc))
        print("f1:",statistics.mean(f1_svmc))
        
        print("\nXGBoost")
        print("accuracy:",statistics.mean(accuracy_xgbc))
        print("precision:",statistics.mean(precision_xgbc))
        print("recall:",statistics.mean(recall_xgbc))
        print("f1:",statistics.mean(f1_xgbc))
        
        print("\nARF")
        print("accuracy:",statistics.mean(accuracy_arfc))
        print("precision:",statistics.mean(precision_arfc))
        print("recall:",statistics.mean(recall_arfc))
        print("f1:",statistics.mean(f1_arfc))
        
        print("\nHTC")
        print("accuracy:",statistics.mean(accuracy_htc))
        print("precision:",statistics.mean(precision_htc))
        print("recall:",statistics.mean(recall_htc))
        print("f1:",statistics.mean(f1_htc))
        

        print("----------------------------------------")


if __name__ == '__main__':

    # finetune(2)

    # exit(0)
    # print("iniciando")
    
    for filename in os.listdir("bases"):
    
        # if "phase2_agregado_ab_tcp_50" not in filename:
        #     continue

        if "final" in filename:
            phaseX("bases/"+filename, 3)

        if "phase1" in filename:
            phaseX("bases/"+filename, 1)
        elif "phase2" in filename:
            phaseX("bases/"+filename, 2)
    
    
    
def outro():
    exit(0)


    print("Modo de uso: main.py --file_name <nome-arquivo.csv>")

    filename = sys.argv[2]

    lista_files = []






    #chunksize = 10 ** 6
    print("Classificando Base: ", filename)
    
    colunas_drop = ["service_class", "app_class", "qos_class"]

    be_downup_apps = ["ftps_down", "scp_down", "scp_up", "ftps_updown", "ftps_up","bittorrent","skype_updown"]
    be_outros_apps = ["www","email"]

    video_real_apps = ["handgout", "skype", "facebook", "ufc1080p"]
    audio_real_apps = ["handgout", "skype", "facebook", "voipbuster", "hangouts"]

    video_estatico_apps = ["netflix", "youtube", "vimeo"]
    audio_estatico_apps = ["vimeo", "spotify"]

    game_apps = ["csdm", "chess"]

    # mover para be
    chat_real = ["skype", "hangouts", "icq", "facebook", "handgout", "aim", "gmail"]

    data = pd.read_csv(filename, sep=',', encoding="UTF-8")

    print("antes:",len(data))
    #remover todos os tcp para analiser
    data = data.drop(data[data["proto"] == 0].index)

    print("depois:",len(data))

    print("video_real", len(data.query("""service_class=="video_real" """)))
    print("audio_real", len(data.query("""service_class=="audio_real" """)))
    print("video_estatico", len(data.query("""service_class=="video_estatico" """)))
    print("audio_estatico", len(data.query("""service_class=="audio_estatico" """)))

    # print(data.columns)
    # exit(0)
    app_type = data["app_class"].to_list()
    app_class = data["service_class"].to_list()
    service_class = data["service_class"].to_list()

    for s in service_class:
        if s == "chat_real":
            s = 'be'
        elif s == "video_real":
            s = "real_time"
        elif s == 'audio_real':
            s = "real_time"
        elif s == 'game':
            s = "real_time"
        elif s == "video_estatico":
            s = "non_real_time"
        elif s == "audio_estatico":
            s = "non_real_time"

    
    data = data.drop(columns=colunas_drop , axis=1, errors='ignore')

    
    
    print(data.columns, len(data.columns))

    X_train, X_test, y_train, y_test = train_test_split(data, service_class, 
                                   random_state=104,  
                                   test_size=0.25,  
                                   shuffle=True) 

    rfc = ClassificadorBatch(nome_classificador="RandomForest", tcp_only=False, two_ways=False)

    rfc.train_model(X_train, y_train)

    y_pred = rfc.test_all_model(X_test)

    print(accuracy_score(y_test, y_pred))
    data = None
    rfc = None

    X_train = X_test = y_train = y_test = None

    exit(0)

    data = data.drop(columns=['id','app_class', 'service_class','qos_class'])
            
    cross_validation_folds = 5
    qtd_dados_total = len(classes_df)

    qtd_dados_per_fold = int(qtd_dados_total/cross_validation_folds)

    precision_rfc = []
    precision_dtc = []
    precision_xgbc = []
    precision_svmc = []

    accuracy_rfc = []
    accuracy_dtc = []
    accuracy_xgbc = []
    accuracy_svmc = []

    f1_rfc = []
    f1_dtc = []
    f1_xgbc = []
    f1_svmc = []

    recall_rfc = []
    recall_dtc = []
    recall_xgbc = []
    recall_svmc = []

    # primeiro vamos testar os hyperparameters
    # #nao vamos optar por 80/20, mas por crossvalidation
    # # X_train, X_test, y_train, y_test = train_test_split(df, classes_df, test_size=0.2, random_state=42)# Treinando modelo
    # #criando o crossvalidation
    # for i in range(0, cross_validation_folds):
    #     # print(i*dadospb, '->',i*dadospb+dadospb-1)
    
    #     rfc = ClassificadorBatch(nome_classificador="RandomForest", tcp_only=True, two_ways=True)
    #     dtc = ClassificadorBatch(nome_classificador="DecisionTree", tcp_only=False, two_ways=False)
    #     xgbc = ClassificadorBatch(nome_classificador="XGBoost", tcp_only=False, two_ways=False)
    #     svmc = ClassificadorBatch(nome_classificador="SVM", tcp_only=False, two_ways=False)
        
    #     for j in range(0, cross_validation_folds):
        
    #         ##esse eh o de teste
    #         if i == j:
    #             continue
    #         # print(X_train.iloc[i*dadospb:i*dadospb+dadospb-1])
            
    #         # print('a: ', j*dadospb, '->', j*dadospb+dadospb-1)
    #         X_train = data.iloc[j*qtd_dados_per_fold:j*qtd_dados_per_fold+qtd_dados_per_fold-1]

    #         y_train = classes_df[j*qtd_dados_per_fold:j*qtd_dados_per_fold+qtd_dados_per_fold-1]
    
    #         # tinicio_rf = time.monotonic()
    #         rfc.train_model(X_train, y_train)
    #         dtc.train_model(X_train, y_train)
    #         xgbc.train_model(X_train, y_train)
    #         svmc.train_model(X_train, y_train)
    #         # tempo_treino_rf += time.monotonic()-tinicio_rf        
    
    #     X_test = data.iloc[i*qtd_dados_per_fold:i*qtd_dados_per_fold+qtd_dados_per_fold-1]
    #     y_test = classes_df[i*qtd_dados_per_fold:i*qtd_dados_per_fold+qtd_dados_per_fold-1]

    #     tempo_teste_svm = 0.0
    #     tempo_teste_rf = 0.0
    #     tempo_teste_dt = 0.0  
    
    #     # tinicio_rf = time.monotonic()
    #     y_pred_rfc = rfc.test_all_model(X_test)
    #     # tempo_teste_rf += time.monotonic() - tinicio_rf
    #     y_pred_dtc = dtc.test_all_model(X_test)
    #     y_pred_xgb = xgbc.test_all_model(X_test)
    #     y_pred_svmc = svmc.test_all_model(X_test)
        
    #     #metricas
    #     #RFC
    #     accuracy_rfc.append(accuracy_score(y_test, y_pred_rfc))
    #     precision_rfc.append(precision_score(y_test, y_pred_rfc,average='macro'))
    #     recall_rfc.append(recall_score(y_test, y_pred_rfc,average='macro'))
    #     f1_rfc.append(f1_score(y_test, y_pred_rfc,average='macro'))
        
    #     #DTC
    #     accuracy_dtc.append(accuracy_score(y_test, y_pred_dtc))
    #     precision_dtc.append(precision_score(y_test, y_pred_dtc,average='macro'))
    #     recall_dtc.append(recall_score(y_test, y_pred_dtc,average='macro'))
    #     f1_dtc.append(f1_score(y_test, y_pred_dtc,average='macro'))
        
    #     #XGB
    #     accuracy_xgbc.append(accuracy_score(y_test, y_pred_xgb))
    #     precision_xgbc.append(precision_score(y_test, y_pred_xgb,average='macro'))
    #     recall_xgbc.append(recall_score(y_test, y_pred_xgb,average='macro'))
    #     f1_xgbc.append(f1_score(y_test, y_pred_xgb,average='macro'))
        
    #     #SVM        
    #     accuracy_svmc.append(accuracy_score(y_test, y_pred_svmc))
    #     precision_svmc.append(precision_score(y_test, y_pred_svmc,average='macro'))
    #     recall_svmc.append(recall_score(y_test, y_pred_svmc,average='macro'))
    #     f1_svmc.append(f1_score(y_test, y_pred_svmc,average='macro'))
    



    print("Refazendo os testes:")

        #criando o crossvalidation
    for i in range(0, cross_validation_folds):
        # print(i*dadospb, '->',i*dadospb+dadospb-1)
    
        RandomForestClassifier(n_estimators=parameters_rfc)
        rfc = ClassificadorBatch(nome_classificador="RandomForest", tcp_only=True, two_ways=True)
        dtc = ClassificadorBatch(nome_classificador="DecisionTree", tcp_only=False, two_ways=False)
        xgbc = ClassificadorBatch(nome_classificador="XGBoost", tcp_only=False, two_ways=False)
        svmc = ClassificadorBatch(nome_classificador="SVM", tcp_only=False, two_ways=False)
        
        for j in range(0, cross_validation_folds):
        
            ##esse eh o de teste
            if i == j:
                continue
            # print(X_train.iloc[i*dadospb:i*dadospb+dadospb-1])
            
            # print('a: ', j*dadospb, '->', j*dadospb+dadospb-1)
            X_train = data.iloc[j*qtd_dados_per_fold:j*qtd_dados_per_fold+qtd_dados_per_fold-1]

            y_train = classes_df[j*qtd_dados_per_fold:j*qtd_dados_per_fold+qtd_dados_per_fold-1]
    
            # tinicio_rf = time.monotonic()
            rfc.train_model(X_train, y_train)
            dtc.train_model(X_train, y_train)
            xgbc.train_model(X_train, y_train)
            svmc.train_model(X_train, y_train)
            # tempo_treino_rf += time.monotonic()-tinicio_rf        
    
        X_test = data.iloc[i*qtd_dados_per_fold:i*qtd_dados_per_fold+qtd_dados_per_fold-1]
        y_test = classes_df[i*qtd_dados_per_fold:i*qtd_dados_per_fold+qtd_dados_per_fold-1]

        tempo_teste_svm = 0.0
        tempo_teste_rf = 0.0
        tempo_teste_dt = 0.0  
    
        # tinicio_rf = time.monotonic()
        y_pred_rfc = rfc.test_all_model(X_test)
        # tempo_teste_rf += time.monotonic() - tinicio_rf
        y_pred_dtc = dtc.test_all_model(X_test)
        y_pred_xgb = xgbc.test_all_model(X_test)
        y_pred_svmc = svmc.test_all_model(X_test)
        
        #metricas
        #RFC
        accuracy_rfc.append(accuracy_score(y_test, y_pred_rfc))
        precision_rfc.append(precision_score(y_test, y_pred_rfc,average='macro'))
        recall_rfc.append(recall_score(y_test, y_pred_rfc,average='macro'))
        f1_rfc.append(f1_score(y_test, y_pred_rfc,average='macro'))
        
        #DTC
        accuracy_dtc.append(accuracy_score(y_test, y_pred_dtc))
        precision_dtc.append(precision_score(y_test, y_pred_dtc,average='macro'))
        recall_dtc.append(recall_score(y_test, y_pred_dtc,average='macro'))
        f1_dtc.append(f1_score(y_test, y_pred_dtc,average='macro'))
        
        #XGB
        accuracy_xgbc.append(accuracy_score(y_test, y_pred_xgb))
        precision_xgbc.append(precision_score(y_test, y_pred_xgb,average='macro'))
        recall_xgbc.append(recall_score(y_test, y_pred_xgb,average='macro'))
        f1_xgbc.append(f1_score(y_test, y_pred_xgb,average='macro'))
        
        #SVM        
        accuracy_svmc.append(accuracy_score(y_test, y_pred_svmc))
        precision_svmc.append(precision_score(y_test, y_pred_svmc,average='macro'))
        recall_svmc.append(recall_score(y_test, y_pred_svmc,average='macro'))
        f1_svmc.append(f1_score(y_test, y_pred_svmc,average='macro'))
    