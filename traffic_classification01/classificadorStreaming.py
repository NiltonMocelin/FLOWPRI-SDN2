import pandas as pd
import seaborn as sn
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split, GridSearchCV

from pandas import DataFrame
import numpy as np
np.float = float
from skmultiflow.trees import HoeffdingTreeClassifier
from skmultiflow.meta import AdaptiveRandomForestClassifier


from sklearn.metrics import accuracy_score, confusion_matrix, precision_score, recall_score,f1_score, ConfusionMatrixDisplay
import time


# Classificar fluxo em Aplicação -- mais específica ou mais genérica? (youtube, twitch, games, voip)
# 

class ClassificadorStreaming:

    classificador = None

    def __init__(self, nome_classificador, params=None):

        self.nomeClassificador = nome_classificador

        if "AdaptiveRandomForest" in nome_classificador:
            self.classificador = AdaptiveRandomForestClassifier(params)
        else:
            #"HoeffdingTree" in nome_classificador:
            self.classificador = HoeffdingTreeClassifier(params)
        
    
    def load_classifier():
        return

    def train_model(self, X_train:DataFrame, Y_train:list, partial_fit= True):
        # Y-train precisa ser de inteiros  (lista de classes) [0,1,2,3] 
        tempo_treino = time.monotonic()
        print("[treino]iniciado ", self.nomeClassificador)
        if partial_fit:

            for x,y in zip(X_train,Y_train):
                X_train_stream = np.array([x.values.flatten().tolist()])
                y_train_stream = np.array([y])

                self.classificador.partial_fit(X_train_stream, y_train_stream)

        else:
            self.classificador.fit(X_train.to_numpy(), np.array(Y_train))
        tempo_treino = time.monotonic()- tempo_treino
        print("[treino]feito tempo:", tempo_treino)
        return tempo_treino
        
    def test_one_model(self, x_test):
        # x_test == uma linha de um dataframe
        print("[test]iniciado")             
        tempo_treino = time.monotonic()
        y_pred = self.classificador.predict(x_test.to_numpy())
        tempo_treino = time.monotonic()- tempo_treino
        print("[test]finalizado tempo:", tempo_treino - time.monotonic())
        return tempo_treino, y_pred, x_test

    def test_all_model(self, X_test:DataFrame):
        print("[test]iniciado")
        y_pred = []
        
        tempo_treino = time.monotonic()
        
        y_pred.append(self.classificador.predict(X_test.to_numpy()))
        tempo_treino = time.monotonic()- tempo_treino
        
        print("[test]finalizado tempo:", tempo_treino - time.monotonic())
        
        return tempo_treino, X_test, y_pred
        

    def hyper_parametros(self):
        return self.classificador.get_params()

    def hyperparameter_tune(self, X:DataFrame, Y:list):
        """Realizar grid search"""

        param_grid = {}

        if self.nomeClassificador == "AdaptiveRandomForest":
            param_grid = {'grace_period': [30, 50, 100], 'split_criterion': ['gini', 'info_gain'], 'random_state': [42]}
        else:
            param_grid ={'grace_period': [30, 10, 100], 'split_criterion': ['gini', 'info_gain'], 'random_state': [42]}
        
        print("[Inicio] Fine Tuning -> parametros testados (grid_search): ", param_grid)

        grid_search = GridSearchCV(estimator=self.classificador, param_grid=param_grid, cv= 5, n_jobs=-1,scoring='accuracy')
        grid_search.fit(X.to_numpy(), np.arra(Y))

        best_params = grid_search.best_params_
        print("[Fim] Os melhores parametros foram: ", best_params)

        self.classificador = grid_search.best_estimator_
        return best_params