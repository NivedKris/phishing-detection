# Phishing Website Detection Using Machine Learning

## Overview

This project aims to detect phishing websites using machine learning techniques. The detection system extracts features from URLs, domain information, and HTML/JavaScript content to classify websites as either phishing or legitimate.

## Features

The feature extraction process involves analyzing various attributes of URLs, domains, and webpage content. Below is a detailed description of the extracted features:

### Address Bar Based Features

1. **Domain of the URL (`Domain`)**: Extracts the domain from the URL, removing the "www." prefix if present.
2. **Checks for IP address in URL (`Have_IP`)**: Checks if the URL contains an IP address.
3. **Checks the presence of "@" in URL (`Have_At_Sign`)**: Checks if the URL contains an "@" symbol.
4. **Finding the length of URL and categorizing (`URL_Length`)**: Checks if the URL length is greater than or equal to 54 characters.
5. **Gives the number of '/' in URL (`URL_Depth`)**: Counts the depth of the URL by counting the number of slashes.
6. **Checking for redirection '//' in the URL (`Redirection`)**: Checks for the presence of '//' in the URL path.
7. **Existence of “HTTPS” Token in the Domain Part of the URL (`https_Domain`)**: Checks if the domain part of the URL contains "https".
8. **Checking for Shortening Services in URL (`Tiny_URL`)**: Checks if the URL uses shortening services.
9. **Checking for Prefix or Suffix Separated by (-) in the Domain (`Prefix/Suffix`)**: Checks if the domain contains a hyphen.

### Domain Based Features

10. **DNS Record availability (`DNS_Record`)**: Checks if the DNS record exists for the domain.
11. **Web traffic (`Web_Traffic`)**: Uses Alexa ranking to determine the web traffic of the domain.
12. **Survival time of domain (`Domain_Age`)**: Calculates the age of the domain.
13. **End time of domain (`Domain_End`)**: Calculates the time until the domain expires.

### HTML and JavaScript Based Features

14. **IFrame Redirection (`iFrame`)**: Checks for the presence of iframe redirection in the HTML content.
15. **Checks the effect of mouse over on status bar (`Mouse_Over`)**: Checks if there is JavaScript code that changes the status bar on mouse over.
16. **Checks the status of the right-click attribute (`Right_Click`)**: Checks if the right-click functionality is disabled.
17. **Checks the number of forwardings (`Web_Forwards`)**: Checks the number of redirects the website has.

## Model

The model used for detecting phishing websites is AdaBoost, trained on a dataset of 10,000 URLs. The dataset was preprocessed similarly to the input URLs to ensure consistency in feature extraction. The AdaBoost model achieved an R² score of 8.62, indicating its effectiveness in distinguishing between phishing and legitimate websites.

### Comparison with Other Models

To benchmark the performance of the AdaBoost model, we compared it with some other commonly used models:

- **Logistic Regression**: R2 score:8.14
- **Random Forest**: R2 score:8.27
- **Support Vector Machine (SVM)**: R2 score:8.32

The AdaBoost model outperformed these models in terms of accuracy and R² score of 8.62, making it the preferred choice for this project.

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/phishing-detection.git
    cd phishing-detection
    ```

2. Install the required libraries:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

To run the phishing detection system, use the following command:
```bash
python app.py
```

## File Descriptions

### `feature_extraction.py`

This file contains the functions for extracting features from URLs, domains, and HTML/JavaScript content. It includes functions for each feature described above.

### `app.py`

This is the main application file. It imports the `feature_extraction` module, takes a URL as input, and prints the extracted features.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contact

For any questions or suggestions, please contact [Nived krishna](mailto:nithupd@gmail.com).
