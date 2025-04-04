import pandas as pd
import seaborn as sn
import matplotlib.pyplot as plt

from sklearn.cluster import KMeans

# Classificar fluxo em QOS (Largura de banda) :: cada grupo de aplicação tem sua qualidade

class QOS_TCPClassificador:

    # aqui utilizar basicamente as colunas de largura de banda

    def train_model_all(self, x_train, y_train):
        self.kmeans = KMeans(n_clusters = 3, random_state = 0, n_init='auto')
        self.kmeans.fit(x_train)

        print("iniciado")

    def test_model_all(self, x_test):
        return self.kmeans.predict(self.X_test)


class QOS_UDPClassificador:

    def train_model_all(self, x_train, y_train, classes:list):
        self.kmeans = KMeans(n_clusters = 3, random_state = 0, n_init='auto')
        self.kmeans.fit(x_train)

        print("iniciado")

    def test_model_all(self, x_test):
        return self.kmeans.predict(self.X_test)