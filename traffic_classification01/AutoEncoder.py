# python
# main-Ref: https://www.geeksforgeeks.org/ml-classifying-data-using-an-auto-encoder/?ref=oin_asr1
# other-ref: https://github.com/xxl4tomxu98/autoencoder-feature-extraction/blob/main/autoencoder-classification.ipynb
import pandas as pd  
import numpy as np 
from sklearn.model_selection import train_test_split  
from sklearn.linear_model import LogisticRegression 
from sklearn.svm import SVC 
from sklearn.metrics import accuracy_score 
from sklearn.preprocessing import MinMaxScaler  
from sklearn.manifold import TSNE 
import matplotlib.pyplot as plt 
import seaborn as sns 
from keras.layers import Input, Dense 
from keras.models import Model, Sequential 
from keras import regularizers 

class AutoEncoder:

    def build(self, X_train):
        # Building the Input Layer 
        self.input_layer = Input(shape =(X_train.shape[1], )) #shape retorna as dimensoes
        
        # Building the Encoder network 
        self.encoded = Dense(100, activation ='tanh', 
                        activity_regularizer = regularizers.l1(10e-5))(self.input_layer) 
        self.encoded = Dense(50, activation ='tanh', 
                        activity_regularizer = regularizers.l1(10e-5))(self.encoded) 
        self.encoded = Dense(25, activation ='tanh', 
                        activity_regularizer = regularizers.l1(10e-5))(self.encoded) 
        self.encoded = Dense(12, activation ='tanh', 
                        activity_regularizer = regularizers.l1(10e-5))(self.encoded) 
        self.encoded = Dense(6, activation ='relu')(self.encoded) 
        
        # Building the Decoder network 
        self.decoded = Dense(12, activation ='tanh')(self.encoded) 
        self.decoded = Dense(25, activation ='tanh')(self.decoded) 
        self.decoded = Dense(50, activation ='tanh')(self.decoded) 
        self.decoded = Dense(100, activation ='tanh')(self.decoded) 
        
        # Building the Output Layer 
        self.output_layer = Dense(X_train.shape[1], activation ='relu')(self.decoded) 

        # Defining the parameters of the Auto-encoder network 
        self.autoencoder = Model(self.input_layer, self.output_layer) 
        self.autoencoder.compile(optimizer ="adadelta", loss ="mse") 
        self.hidden_representation = Sequential() 

    #fit_all -> train 
    # [ref2] ->Next, we can train the model to reproduce the input and keep track of the performance of the model on the hold-out test set.
    def fit(self, X_train):
        # Scaling the data to make it suitable for the auto-encoder 
        # X_scaled = MinMaxScaler().fit_transform(X) 
        # X_normal_scaled = X_scaled[y == 0] 
        # X_fraud_scaled = X_scaled[y == 1] 

        # Training the Auto-encoder network 
        self.autoencoder.fit(X_train, X_train,  
                        batch_size = 16, epochs = 10,  
                        shuffle = True, validation_split = 0.20) 
        
        self.hidden_representation.add(self.autoencoder.layers[0]) 
        self.hidden_representation.add(self.autoencoder.layers[1]) 
        self.hidden_representation.add(self.autoencoder.layers[2]) 
        self.hidden_representation.add(self.autoencoder.layers[3]) 
        self.hidden_representation.add(self.autoencoder.layers[4])
    
    def predict(self, X_test):
        return self.hidden_representation.predict(X_test) 
    
    def plot(self, encoded_X, encoded_y):

        # # Separating the points encoded by the Auto-encoder as normal and fraud 
        # normal_hidden_rep = self.hidden_representation.predict(X_normal_scaled) 
        # fraud_hidden_rep = self.hidden_representation.predict(X_fraud_scaled) 

        # # Combining the encoded points into a single table  
        # encoded_X = np.append(normal_hidden_rep, fraud_hidden_rep, axis = 0) 
        # y_normal = np.zeros(normal_hidden_rep.shape[0]) 
        # y_fraud = np.ones(fraud_hidden_rep.shape[0]) 
        # encoded_y = np.append(y_normal, y_fraud) 

        # Plotting the encoded points 
        self._tsne_plot(encoded_X, encoded_y) 


    def _tsne_plot(x, y): 
      
        # Setting the plotting background 
        sns.set(style ="whitegrid") 

        tsne = TSNE(n_components = 2, random_state = 0) 

        # Reducing the dimensionality of the data 
        X_transformed = tsne.fit_transform(x) 
    
        plt.figure(figsize =(12, 8)) 

        # Building the scatter plot 
        plt.scatter(X_transformed[np.where(y == 0), 0],  
                    X_transformed[np.where(y == 0), 1], 
                    marker ='o', color ='y', linewidth ='1', 
                    alpha = 0.8, label ='Normal') 
        plt.scatter(X_transformed[np.where(y == 1), 0], 
                    X_transformed[np.where(y == 1), 1], 
                    marker ='o', color ='k', linewidth ='1', 
                    alpha = 0.8, label ='Fraud') 
    
        # Specifying the location of the legend 
        plt.legend(loc ='best') 

        # Plotting the reduced data 
        plt.show() 