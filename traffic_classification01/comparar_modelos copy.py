

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

from sklearn.model_selection import train_test_split, KFold

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

def finetune():
    # usar um arquivo para fine tuning -- ab_10pkts da vida para be vs qos, 50 pkts que é bem menor
    
    filename = "bases/phase1_agregado_ab_50pkts.csv"

    data = pd.read_csv(filename, sep=',', encoding="UTF-8")

    # pegar apenas  metade da base, metade de cada classe
    app_type = data["app_class"].to_list()
    app_class = data["service_class"].to_list()
    service_class = data["service_class"].to_list()

    for serv in service_class:
        if serv != "be":
            serv = "qos"

    colunas_drop = ["service_class", "app_class", "qos_class"]

    data = data.drop(columns=colunas_drop , axis=1, errors='ignore')
    
    rfc = ClassificadorBatch(nome_classificador="RandomForest")
    dtc = ClassificadorBatch(nome_classificador="DecisionTree")
    xgbc = ClassificadorBatch(nome_classificador="XGBoost")
    svmc = ClassificadorBatch(nome_classificador="SVM")
    arf = ClassificadorStreaming(nome_classificador="AdaptiveRandomForest")
    hft = ClassificadorStreaming(nome_classificador="HoeffdingTree")


    ## ress:
    #[Inicio] Fine Tuning -> parametros testados (grid_search):  {'n_estimators': [25, 50, 100], 'max_features': ['sqrt', 'log2', None], 'max_depth': [3, 6, 9], 'max_leaf_nodes': [3, 6, 9]}
    #[Fim] Os melhores parametros foram:  {'max_depth': 6, 'max_features': 'log2', 'max_leaf_nodes': 9, 'n_estimators': 25}
    #{'max_depth': 6, 'max_features': 'log2', 'max_leaf_nodes': 9, 'n_estimators': 25}
    #[Inicio] Fine Tuning -> parametros testados (grid_search):  {'max_depth': [10, 30, None], 'min_samples_split': [2, 5, 10], 'min_samples_leaf': [1, 2, 4]}
    #[Fim] Os melhores parametros foram:  {'max_depth': None, 'min_samples_leaf': 4, 'min_samples_split': 10}
    #{'max_depth': None, 'min_samples_leaf': 4, 'min_samples_split': 10}


    print("comecando")
    # print(rfc.hyperparameter_tune(data, service_class))
    # print(dtc.hyperparameter_tune(data, service_class))
    print(svmc.hyperparameter_tune(data, service_class))
    print(arf.hyperparameter_tune(data, service_class))
    print(hft.hyperparameter_tune(data, service_class))
    print(xgbc.hyperparameter_tune(data, service_class))

    return

def phase0(filename):

    colunas_drop = ["service_class", "app_class", "qos_class"]

    data = pd.read_csv(filename, sep=',', encoding="UTF-8")


def phaseX(filename, phase):

    # if phase != 1:
    #     return
    if phase ==1:
        return

    colunas_drop = ["service_class", "app_class", "qos_class"]
    print("classificacao phase ", phase)

    classes_mais_dificeis = {"be":[],"qos":[],"video_real":[],"audio_real":[],"video_estatico":[],"video_real":[], "game":[], "chat_real":[], 0:0, 1:0,2:0,3:0,4:0,5:0,6:0,7:0}

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

        # data = data.replace(np.nan, 0)

        # app_type = data["app_class"].to_list()
        # app_class = data["service_class"].to_list()
        # service_class = data["service_class"].to_list()

        #encontrando valores NaN ?
        # print(data.isnull().any())
        classe_list = data["service_class"].to_list()

        if phase == 1:
            for i in range(0, len(classe_list)):
                if classe_list[i] != "be":
                    classe_list[i] = "qos"

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

            # rfc = RandomForestClassifier()
            # dtc = DecisionTreeClassifier()
            # svc = SVC()
            # arfc = AdaptiveRandomForestClassifier()
            # htc = HoeffdingTreeClassifier()

            xgbc = xgb.XGBClassifier(tree_method="hist", random_state=42)
            
            y_train_xgb = []
            y_test_xgb = []
            desconto = 6 if phase==1 else 0
            for i in range(0,len(y_train)):
                y_train_xgb.append(classes_streaming[y_train[i]]-desconto)
            for i in range(0,len(y_test)):
                y_test_xgb.append(classes_streaming[y_test[i]]-desconto)
            

            # print(y_train_xgb)
            # print(y_train)
            xgbc.fit(X_train,y_train_xgb)

            y_pred = xgbc.predict(X_test)

            # print(y_pred.tolist())
            accuracy_xgbc.append(accuracy_score(y_test_xgb, y_pred))
            precision_xgbc.append(precision_score(y_test_xgb, y_pred,average='macro'))
            recall_xgbc.append(recall_score(y_test_xgb, y_pred,average='macro'))
            f1_xgbc.append(f1_score(y_test_xgb, y_pred,average='macro'))

        print("resultados ", filename, ' phase: ', phase)
        # return
        # print("RFC")
        # print("accuracy:",statistics.mean(accuracy_rfc))
        # print("precision:",statistics.mean(precision_rfc))
        # print("recall:",statistics.mean(recall_rfc))
        # print("f1:",statistics.mean(f1_rfc))

        # print("\nDTC")
        # print("accuracy:",statistics.mean(accuracy_dtc))
        # print("precision:",statistics.mean(precision_dtc))
        # print("recall:",statistics.mean(recall_dtc))
        # print("f1:",statistics.mean(f1_dtc))
        
        # print("\nSVC")
        # print("accuracy:",statistics.mean(accuracy_svmc))
        # print("precision:",statistics.mean(precision_svmc))
        # print("recall:",statistics.mean(recall_svmc))
        # print("f1:",statistics.mean(f1_svmc))
        
        print("\nXGBoost")
        print("accuracy:",statistics.mean(accuracy_xgbc))
        print("precision:",statistics.mean(precision_xgbc))
        print("recall:",statistics.mean(recall_xgbc))
        print("f1:",statistics.mean(f1_xgbc))
        
        # print("\nARF")
        # print("accuracy:",statistics.mean(accuracy_arfc))
        # print("precision:",statistics.mean(precision_arfc))
        # print("recall:",statistics.mean(recall_arfc))
        # print("f1:",statistics.mean(f1_arfc))
        
        # print("\nHTC")
        # print("accuracy:",statistics.mean(accuracy_htc))
        # print("precision:",statistics.mean(precision_htc))
        # print("recall:",statistics.mean(recall_htc))
        # print("f1:",statistics.mean(f1_htc))
        

        print("----------------------------------------")


if __name__ == '__main__':

    # finetune()
    print("iniciando")
    
    for filename in os.listdir("bases"):
    
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
    