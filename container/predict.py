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

#input the data 

#and keep it in a file 

def predictResult(input):
    sc = MinMaxScaler()
    input = input.to_numpy()
    input = sc.fit_transform(input.reshape(1,-1))
    model = load_model('ann.h5')
    y_pred = model.predict(input)
    y_res = y_pred.argmax(axis=1)

    return y_res
