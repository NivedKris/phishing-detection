from flask import Flask, render_template, request, redirect, url_for
import pickle
import pandas as pd  # Add this import statement
from feature_extraction import feature_extraction


app = Flask(__name__)

# Load the trained model
with open('test.pkl', 'rb') as model_file:
    loaded_model = pickle.load(model_file)

# Route to render the home page
@app.route('/')
def home():
    return render_template('index.html')

# Route to handle the form submission and classify the URL
@app.route('/classify', methods=['POST'])
def classify():
    if request.method == 'POST':
        url = request.form['url']

        # Extract features using the feature_extraction function
        features_list = feature_extraction(url)

        # Convert the features to a DataFrame
        features_df = pd.DataFrame([features_list], columns=[
            'Domain', 'Have_IP', 'Have_At', 'URL_Length', 'URL_Depth',
            'Redirection', 'https_Domain', 'TinyURL', 'Prefix/Suffix',
            'DNS_Record', 'Web_Traffic', 'Domain_Age', 'Domain_End',
            'iFrame', 'Mouse_Over', 'Right_Click', 'Web_Forwards'
        ])

        # Drop the 'Label' column (not needed for prediction)
        # Drop the 'Label' and 'Domain' columns (not needed for prediction)
        features_for_prediction = features_df.drop(['Label', 'Domain'], axis=1, errors='ignore')
#

        # Make the prediction
        prediction = loaded_model.predict(features_for_prediction)

        # Display the result
        result = "Phishing" if prediction[0] == 1 else "Legitimate"

        return render_template('result.html', result=result)

@app.route('/restart', methods=['POST'])
def restart_system():
    # Add any cleanup or reset code here
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
