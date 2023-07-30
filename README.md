# Phishing_URL_Detection_Using_Machine_Learning
This is a software developed using python and Machine Learning to find whether the given URL is safe or not. The Classifiers used in this to train are Random Forest, Decision Trees , Light GBM, Logistic Regression and Support vector Machine. 
Dataset is taken from Kaggle.
First Phishing_URL_Detection_Using_Sequential_Feature_Selector file contains a csv file having 30 features.
I trained the classifiers with the dataset and noted the Accuracy Measures.
Now to reduce the complexity I applied Sequential Feature Selector to the dataset and then noted the Accuracy Measures.
So i got the similar accuracy as the original dataset with just 20 features after applying the sequential feature selector.
Now i also applied Principal Componant Analysis PCA to the dataset with 20 features But the Accuracy measures are very poor compared to sequential feature selector.
So finally i got the accuracy of 96.6% using random forest Classifier and Sequential Feature Selector.
And to run this software open the phishing_url_interface file and open app.py and run it (ensure that flask is installed in your system).
Thats it.
