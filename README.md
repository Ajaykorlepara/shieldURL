Access the website : https://verifyurl.onrender.com/
Malicious URL Detection with XGBoost
This repository contains a Jupyter Notebook demonstrating the process of detecting malicious URLs using XGBoost. The notebook covers data loading, extensive feature engineering from URLs, model training, hyperparameter tuning, and saving the trained model for future predictions.

Table of Contents
Introduction

Features

Installation

Dataset

Usage

Feature Extraction

Model Training

Hyperparameter Tuning

Prediction

Saving and Loading Models

Contributing

License

Introduction
Phishing and malicious URLs are significant threats in cybersecurity. This project aims to build a robust classification model using XGBoost to identify such URLs based on various extracted features. The approach involves transforming raw URL strings into numerical features that can be used by machine learning algorithms.

Features
URL Feature Engineering: Extracts numerous features from URLs, such as IP address presence, URL length, suspicious words, digit/letter counts, and more.

XGBoost Classifier: Utilizes the powerful XGBoost algorithm for classification.

Hyperparameter Tuning: Employs GridSearchCV for optimizing XGBoost model parameters to achieve better performance.

Model Persistence: Saves the trained model, scaler, and label encoder using pickle for easy deployment and future use.

Installation
To run this notebook, you need to have Python installed along with the following libraries. You can install them using pip:

Bash

pip install pandas scikit-learn xgboost urllib3 regex tld googlesearch pickle-mixin
Dataset
The dataset used for training is malicious_phish.csv. It should contain at least two columns: url (the URL string) and type (the label indicating the URL's category, e.g., 'benign', 'phishing', 'defacement', 'malware').

The dataset can be downloaded from: KAGGLE
Usage
Clone the repository:

Bash

git clone https://github.com/yourusername/Malicious-URL-Detection.git
cd Malicious-URL-Detection
Download the dataset and place it in the specified DATA_PATH or update the path in the notebook.

Open the Jupyter Notebook:

Bash

jupyter notebook Malicious_URL_Detection.ipynb
Run all cells in the notebook.

Feature Extraction
The notebook defines several functions to extract features from URLs:

having_ip_address(url): Checks if the URL contains an IP address.

abnormal_url(url): Determines if the hostname is present in the URL path.

search_google(url): (Note: This function uses googlesearch which might be rate-limited or require careful handling for large datasets. For production, consider pre-computed features or alternatives.) Checks if the URL appears in Google search results.

count_dot(url): Counts the number of dots in the URL.

count_www(url): Counts occurrences of "www".

count_atrate(url): Counts occurrences of "@".

no_of_dir(url): Counts the number of directories in the URL path.

no_of_embed(url): Counts occurrences of "//" in the URL path.

shortening_service(url): Detects common URL shortening services.

count_https(url): Counts occurrences of "https".

count_http(url): Counts occurrences of "http".

count_per(url): Counts occurrences of "%".

count_ques(url): Counts occurrences of "?".

count_hyphen(url): Counts occurrences of "-".

count_equal(url): Counts occurrences of "=".

url_length(url): Calculates the total length of the URL.

hostname_length(url): Calculates the length of the hostname.

suspicious_words(url): Checks for the presence of suspicious keywords like "PayPal", "login", "bank", etc.

digit_count(url): Counts the number of digits in the URL.

letter_count(url): Counts the number of letters in the URL.

fd_length(url): Calculates the length of the first directory.

tld_length(tld): Calculates the length of the Top-Level Domain (TLD).

These features are then applied to the dataset to create a comprehensive feature set for training.

Model Training
An XGBoost Classifier is trained on the extracted features. The data is split into training and testing sets, and features are scaled using StandardScaler. Labels are encoded using LabelEncoder.

Python

import xgboost as xgb
# ... (data loading and preprocessing)
xgb_model = xgb.XGBClassifier(n_estimators=100)
xgb_model.fit(X_train_scaled, y_train_encoded)
score = xgb_model.score(X_test_scaled, y_test_encoded)
print(f"Test Accuracy: {score:.4f}")
Hyperparameter Tuning
GridSearchCV is used to find the optimal hyperparameters for the XGBoost model, ensuring better performance and generalization.

Python

from sklearn.model_selection import GridSearchCV
param_grid = {
    'n_estimators': [50, 100, 200],
    'max_depth': [3, 5, 7],
    'learning_rate': [0.01, 0.1, 0.2],
    'subsample': [0.8, 1.0]
}
xgb_clf = xgb.XGBClassifier()
grid_search = GridSearchCV(xgb_clf, param_grid, cv=3, scoring='accuracy', verbose=1, n_jobs=-1)
grid_search.fit(X_train_scaled, y_train_encoded)
print('Best parameters:', grid_search.best_params_)
print('Best cross-validation accuracy:', grid_search.best_score_)
Prediction
A preprocess_url function is provided to transform a new URL into the feature vector required by the model. The trained model can then be used to predict the type of the new URL.

Python

# Example prediction
new_url = 'http://secure-bank-account-update.com'
features = preprocess_url(new_url)
features_scaled = scaler.transform([features])
prediction = xgb_model.predict(features_scaled)
predicted_label = label_encoder.inverse_transform(prediction)
print(f"Prediction for URL: {new_url} => {predicted_label[0]}")
Saving and Loading Models
The trained XGBoost model, StandardScaler, and LabelEncoder are saved using Python's pickle module. This allows for easy loading and deployment of the model without retraining.

Python

import pickle
# Save
with open('model.pkl', 'wb') as model_file:
    pickle.dump(xgb_model, model_file)
with open('scaler.pkl', 'wb') as scaler_file:
    pickle.dump(scaler, scaler_file)
with open('label_encoder.pkl', 'wb') as label_encoder_file:
    pickle.dump(label_encoder, label_encoder_file)

# Load (example)
# with open('model.pkl', 'rb') as model_file:
#     loaded_model = pickle.load(model_file)
