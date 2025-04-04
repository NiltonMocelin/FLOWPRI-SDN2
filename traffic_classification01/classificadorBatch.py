import pandas as pd
import seaborn as sn
import matplotlib.pyplot as plt


from sklearn.model_selection import train_test_split, GridSearchCV,RandomizedSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC

from sklearn.metrics import accuracy_score, confusion_matrix, precision_score, recall_score,f1_score, ConfusionMatrixDisplay, classification_report
import time

import xgboost as xgb

from scipy.stats import uniform, randint

import numpy as np

# Classificar fluxo em Aplicação -- mais específica ou mais genérica? (youtube, twitch, games, voip)
# 

# como usar GridSearchCV: https://www.geeksforgeeks.org/svm-hyperparameter-tuning-using-gridsearchcv-ml/


def report_best_scores(results, n_top=3):
    for i in range(1, n_top + 1):
        candidates = np.flatnonzero(results['rank_test_score'] == i)
        for candidate in candidates:
            print("Model with rank: {0}".format(i))
            print("Mean validation score: {0:.3f} (std: {1:.3f})".format(
                  results['mean_test_score'][candidate],
                  results['std_test_score'][candidate]))
            print("Parameters: {0}".format(results['params'][candidate]))
            print("")



class ClassificadorBatch:

    classificador = None

    def __init__(self, nome_classificador, params = None):
        self.nomeClassificador = nome_classificador

        if "RandomForest" in nome_classificador:
            self.classificador = RandomForestClassifier(params)
        elif "DecisionTree" in nome_classificador:
            self.classificador = DecisionTreeClassifier(params)
        elif "XGBoost" in nome_classificador:
            self.classificador = xgb.XGBClassifier(params)
        elif "RNN" in nome_classificador:
            self.classificador = None
        elif "CNN" in nome_classificador:
            self.classificador = None
        else:
            self.classificador = SVC()
    
    def train_model(self, x_train, y_train):
        if self.classificador == None:
            print("Classificador = None")
            return        
        # tempo_treino = time.monotonic()
        print("[treino]iniciado")
        self.classificador.fit(x_train, y_train)
        # tempo_treino = time.monotonic()- tempo_treino
        # print("[treino]feito tempo:", tempo_treino)
        return True
        
    def test_one_model(self, x_test):
        # print("[test]iniciado")
                
        # tempo_treino = time.monotonic()
        y_pred = self.classificador.predict(x_test)
        # tempo_treino = time.monotonic()- tempo_treino
        # print("[test]finalizado tempo:", tempo_treino - time.monotonic())
        return y_pred

    def test_all_model(self, X_test):
        return self.classificador.predict(X_test)
        

    def hyper_parametros(self):
        return self.classificador.get_params()

    def hyperparameter_tune(self, X_train, Y_train):
        """Realizar grid search"""
        
        param_grid = {}

        if self.nomeClassificador == "RandomForest": #https://www.geeksforgeeks.org/random-forest-hyperparameter-tuning-in-python/
            param_grid = { 
                'n_estimators': [25, 50, 100], 
                'max_features': ['sqrt', 'log2', None], 
                'max_depth': [3, 6, 9], 
                'max_leaf_nodes': [3, 6, 9], 
            } 

        elif self.nomeClassificador == "DecisionTree": #https://www.geeksforgeeks.org/how-to-tune-a-decision-tree-in-hyperparameter-tuning/
            param_grid = {
            'max_depth': [10, 30, None],
            'min_samples_split': [2, 5, 10],
            'min_samples_leaf': [1, 2, 4]
            }
        elif self.nomeClassificador == "XGBoost": #https://medium.com/@rithpansanga/optimizing-xgboost-a-guide-to-hyperparameter-tuning-77b6e48e289d
            param_grid = {
            'max_depth': [3, 5, 7],
            'learning_rate': [0.1, 0.01, 0.001],
            'subsample': [0.5, 0.7, 1]
            }

            params = {
                "colsample_bytree": uniform(0.7, 0.3),
                "gamma": uniform(0, 0.5),
                "learning_rate": uniform(0.03, 0.3), # default 0.1 
                "max_depth": randint(2, 6), # default 3
                "n_estimators": randint(100, 150), # default 100
                "subsample": uniform(0.6, 0.4)
            }

            search = RandomizedSearchCV(self.classificador, param_distributions=params, random_state=42, n_iter=200, cv=3, verbose=1, n_jobs=1, return_train_score=True)

            search.fit(X_train, Y_train)

            report_best_scores(search.cv_results_, 1)
            return search.cv_results_
            # param_grid = {    "objective":['multi:softprob', 'binary:logistic'],
            # "num_class": [],      
            # "max_depth" : [],       
            # "learning_rate": [],
            # "subsample":[],        
            # "colsample_bytree" : [], 
            # "n_estimators" : []
            # }
        elif self.nomeClassificador == "SVM": #https://www.geeksforgeeks.org/svm-hyperparameter-tuning-using-gridsearchcv-ml/
            param_grid =  {
            'C':[0.01,1,10],
            'kernel' : ["poly","rbf","sigmoid"],
            'degree' : [1,5,7],
            'gamma' : [0.01,1,10]
            }
        else:
            print("erro nome do classificador não reconhecido!")
            return
        
        print("[Inicio] Fine Tuning -> parametros testados (grid_search): ", param_grid)

        grid_search = GridSearchCV(estimator=self.classificador, param_grid=param_grid, cv= 5, n_jobs=-1,scoring='accuracy')
        grid_search.fit(X_train, Y_train)

        best_params = grid_search.best_params_
        print("[Fim] Os melhores parametros foram: ", best_params)

        self.classificador = grid_search.best_estimator_
        return best_params
    

