import pandas as pd
import seaborn as sn
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split, GridSearchCV

import numpy as np
np.float = float
from sklearn.neighbors import KNeighborsClassifier
from sklearn.cluster import KMeans
from sklearn.cluster import AgglomerativeClustering


from sklearn.metrics import accuracy_score, confusion_matrix, precision_score, recall_score,f1_score, ConfusionMatrixDisplay
import time

from AutoEncoder import AutoEncoder

# Classificar fluxo em Aplicação -- mais específica ou mais genérica? (youtube, twitch, games, voip)
# 

# adicionar isso no artigo depois
# Dependendo do tipo de aplicação existem determinados níveis de QoS --> que são os K neighbours -- por isso determinar o tipo de aplicação antes é interessante !! escrever isso no artigo depois

# pesquisar outros algoritmos de classificacao não supervisionados


# objetivo aqui -> determinar o nível de QoS -- em termos de largura de banda principalmente -- mas vamos ver no geral primeiro, qualquer coisa modificamos para utilizar apenas informações de um tipo: apenas métricas de largura de banda/tam pacotes VS apenas métricas de tempo/IAT 



class classificadorUnsupervised:

    classificador = None

    def __init__(self, nome_classificador, tcp_only=False, two_ways=False):

        self.tcp_only = tcp_only
        self.two_ways = two_ways
        self.nomeClassificador = nome_classificador

        if "KNN" in nome_classificador: # esse na verdade é supervisionado
            self.classificador = KNeighborsClassifier()
        elif "KMeans" in nome_classificador: # esse é não supervisionado:
            #"HoeffdingTree" in nome_classificador:
            self.classificador = KMeans()
        elif "AgglomerativeClustering" in nome_classificador:
            self.classificador = AgglomerativeClustering(n_clusters = 5, affinity = 'euclidean', linkage = 'ward')
        elif "AE" in nome_classificador:
            #AE has some other variations such as Stacked Auto-encoder (SAE), Variational Auto-encoder (VAE) and Denoizing Auto-encoder (DAE). Adversarial Auto-encoder (AAE)
            self.classificador = AutoEncoder()
        elif "T-SNE" in nome_classificador:
            self.classificador = None
        elif "outro" in nome_classificador:
            self.classificador = None

        # Hierarchical Clustering
    
    def train_model(self, X_train, Y_train):
        if self.classificador == None:
            print("Classificador = None")
            return
         
        tempo_treino = time.monotonic()
        print("[treino]iniciado ", self.nomeClassificador)
        self.classificador.fit(X_train, Y_train)# Kmeans ignora Y, pois é unsupervised, já kNN não ignora
        tempo_treino = time.monotonic()- tempo_treino
        print("[treino]feito tempo:", tempo_treino)
        return tempo_treino
        
    def test_one_model(self, x_test):
        print("[test]iniciado")
                
        tempo_treino = time.monotonic()
        y_pred = self.classificador.predict(x_test)
        tempo_treino = time.monotonic()- tempo_treino
        print("[test]finalizado tempo:", tempo_treino - time.monotonic())
        return tempo_treino, y_pred, x_test

    def test_all_model(self, X_test):
        print("[test]iniciado")
        y_pred = []
        
        tempo_treino = time.monotonic()
        
        for input in X_test:
            y_pred.append(self.classificador.predict(input))
        tempo_treino = time.monotonic()- tempo_treino
        
        print("[test]finalizado tempo:", tempo_treino - time.monotonic())
        
        return tempo_treino, X_test, y_pred
        

    def hyper_parametros(self):
        return self.classificador.get_params()

    def fine_tune(self, X_train, Y_train):
        """Realizar grid search"""
        
        # In practice, the k-means algorithm is very fast (one of the fastest clustering algorithms available), but it falls in local minima. That’s why it can be useful to restart it several times.
        if "KMeans" in self.nomeClassificador:
            param_grid = {'random_state':1234, 'n_clusters': [3,5,7,9,11] , 'algorithm': ['lloyd', 'elkan']} # init : define os centroides dos grupos --> como usar: https://towardsdatascience.com/kmeans-hyper-parameters-explained-with-examples-c93505820cd3

        elif "KNN" in self.nomeClassificador:
            param_grid = {'random_state':1234, 'n_neighbors' : [3,5,7,9,11],
                        'weights' : ['uniform','distance'],
                        'metric' : ['minkowski','euclidean','manhattan']}

        elif "AgglomerativeClustering" in self.nomeClassificador:
            # metric: str or callable, default=”euclidean” -> to compute the linkage. Can be “euclidean”, “l1”, “l2”, “manhattan”, “cosine”, or “precomputed”. If linkage is “ward”, only “euclidean” is accepted. If “precomputed”, a distance matrix is needed as input for the fit method. If connectivity is None, linkage is “single” and affinity is not “precomputed” any valid pairwise distance metric can be assigned.
            # linkage{‘ward’, ‘complete’, ‘average’, ‘single’}, default=’ward’
            # distance_thresholdfloat, default=None -->  The linkage distance threshold at or above which clusters will not be merged. If not None, n_clusters must be None and compute_full_tree must be True.
            param_grid = {'random_state':1234, 'n_neighbors' : [3,5,7,9,11],
                        'weights' : ['uniform','distance'],
                        'metric' : ['minkowski','euclidean','manhattan']} # affinity ??? não sei de onde apareceu, não está na documentação

        elif "AAE" in self.nomeClassificador:
            param_grid = {'random_state':1234, 'n_neighbors' : [3,5,7,9,11],
                        'weights' : ['uniform','distance'],
                        'metric' : ['minkowski','euclidean','manhattan']} # affinity ??? não sei de onde apareceu, não está na documentação

        elif "T-SNE" in self.nomeClassificador:
            param_grid = {'random_state':1234, 'n_neighbors' : [3,5,7,9,11],
                        'weights' : ['uniform','distance'],
                        'metric' : ['minkowski','euclidean','manhattan']} # affinity ??? não sei de onde apareceu, não está na documentação

        # KNeighborsClassifier(n_neighbors=neighbor) # encontrar o melhor K
        # sklearn.cluster.AgglomerativeClustering(n_clusters=2, *, metric='euclidean', memory=None, connectivity=None, compute_full_tree='auto', linkage='ward', distance_threshold=None, compute_distances=False)

        
        grid_search = GridSearchCV(estimator=self.classificador, param_grid=param_grid, cv= 5, n_jobs=-1)
        grid_search.fit(X_train, Y_train)

        best_params = grid_search.best_params_
        print("[Fim] Os melhores parametros foram: ", best_params)

        self.classificador = grid_search.best_estimator_
        return 
    


###     code exs: 
# AgglomerativeClustering https://github.com/adv-11/Machine-Learning-A-Z-AI-Python-R-/blob/main/clustering/hierarchical_clustering.ipynb
# KNN https://github.com/adv-11/Machine-Learning-A-Z-AI-Python-R-/blob/main/classification/knn_classification.ipynb
# K-Means https://github.com/adv-11/Machine-Learning-A-Z-AI-Python-R-/blob/main/clustering/k_means.ipynb
# AE main-Ref: https://www.geeksforgeeks.org/ml-classifying-data-using-an-auto-encoder/?ref=oin_asr1
# T-SNE 