import os
from flask import Flask, render_template, request, jsonify
from tensorflow import keras
from urllib.parse import urlparse
import numpy as np
import re
import requests
from groq import Groq
from bs4 import BeautifulSoup
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# Initialize Groq client
GROQ_API_KEY = "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"
groq_client = Groq(api_key=GROQ_API_KEY)

# Load the ML model
def load_model():
    try:
        model = keras.models.load_model('model/Malicious_URL_Prediction.h5')
        print("Model loaded successfully")
        return model
    except Exception as e:
        print(f"Error loading model: {e}")
        return None

model = load_model()

# URL preprocessing
def preprocess_url(url):
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        if url.startswith('www.'):
            url = 'https://' + url
        else:
            url = 'https://www.' + url
    return url

# Feature extraction functions
def fd_length(url):
    urlpath = urlparse(url).path
    try:
        return len(urlpath.split('/')[1])
    except:
        return 0

def digit_count(url):
    return sum(1 for i in url if i.isnumeric())

def letter_count(url):
    return sum(1 for i in url if i.isalpha())

def no_of_dir(url):
    return urlparse(url).path.count('/')

def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)
    return -1 if match else 1
def extract_features(url):
    hostname_length = len(urlparse(url).netloc)
    path_length = len(urlparse(url).path)
    f_length = fd_length(url)

    features = [
        hostname_length,
        path_length,
        f_length,
        url.count('-'),
        url.count('@'),
        url.count('?'),
        url.count('%'),
        url.count('.'),
        url.count('='),
       # url.count('http'),
      #  url.count('https'),
        0,  # Is HTTPS
        0,   # Is HTTP
        url.count('www'),
        digit_count(url),
        letter_count(url),
        no_of_dir(url),
        having_ip_address(url),
        
    ]
    return np.array([features])

def predict_url(url):
    url_lower = url.lower()
    
    # Enhanced ML model prediction
    input_features = extract_features(url)
    pred_test = model.predict(input_features)
    percentage_value = pred_test[0][0] * 100
    
    # Protocol-based confidence thresholds
 #   if url_lower.startswith('https://'):
 #      confidence_threshold = 90
 #      protocol_safety = "🔒 HTTPS Secured"
 #   elif url_lower.startswith('http://'):
 #       confidence_threshold = 60
 #       protocol_safety = "⚠️ HTTP Unsecured"
 #   else:
 #       confidence_threshold = 70
 #       protocol_safety = "❓ Unknown Protocol"
    #try
    # Fixed threshold for all URLs
    confidence_threshold = 70

# Display HTTPS info without influencing prediction
    if url_lower.startswith('https://'):
        protocol_safety = "🔒 HTTPS Used (Not Always Safe)"
    elif url_lower.startswith('http://'):
        protocol_safety = "⚠️ HTTP Used (Unsecured)"
    else:
        protocol_safety = "❓ Unknown Protocol"

   # confidence_threshold = 70
    #if url_lower.startswith('https://'):
     #  protocol_safety = "🔒 HTTPS Secured"
    #elif url_lower.startswith('http://'):
     #  protocol_safety = "⚠️ HTTP Unsecured"
    #else:
     #  protocol_safety = "❓ Unknown Protocol"
    status = 'MALICIOUS' if percentage_value >= confidence_threshold else 'SAFE'
    
    return {
        'url': url,
        'status': status,
        'confidence': f'{percentage_value:.2f}%',
        'protocol_safety': protocol_safety,
        'threshold': confidence_threshold
    }

def fetch_whois_data(url):
    try:
        domain = urlparse(url).netloc
        if domain.startswith('www.'):
            domain = domain[4:]
        
        api_key = "at_Sth08DTygvCX32kwh6loF7zf9iLnK"
        api_url = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
        
        params = {
            "apiKey": api_key,
            "domainName": domain,
            "outputFormat": "JSON"
        }
        
        response = requests.get(api_url, params=params)
        if response.status_code == 200:
            return format_whois_data(response.json())
        return None
    except Exception as e:
        print(f"WHOIS API error: {e}")
        return None

def format_whois_data(raw_data):
    if not raw_data or 'WhoisRecord' not in raw_data:
        return None
    
    whois = raw_data['WhoisRecord']
    registry_data = whois.get('registryData', {})
    
    return {
        'domain_name': {
            'icon': '🌐',
            'label': 'Domain Name',
            'value': whois.get('domainName'),
            'description': 'The registered domain name'
        },
        'registrar': {
            'icon': '📋',
            'label': 'Registrar',
            'value': whois.get('registrarName'),
            'description': 'Company managing the domain registration'
        },
        'creation_date': {
            'icon': '📅',
            'label': 'Created',
            'value': registry_data.get('createdDateNormalized'),
            'description': 'When the domain was first registered'
        },
        'expiry_date': {
            'icon': '⏳',
            'label': 'Expires',
            'value': registry_data.get('expiresDateNormalized'),
            'description': 'When the domain registration expires'
        },
        'organization': {
            'icon': '🏢',
            'label': 'Organization',
            'value': registry_data.get('registrant', {}).get('organization'),
            'description': 'Organization owning the domain'
        },
        'status': {
            'icon': '📊',
            'label': 'Status',
            'value': registry_data.get('status'),
            'description': 'Current domain status and protection measures'
        }
    }

def scrape_and_analyze_content(url):
    try:
        # Scrape website content
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, verify=False, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Extract relevant content (title, meta description, main content)
        title = soup.title.string if soup.title else ''
        meta_desc = soup.find('meta', {'name': 'description'})
        meta_desc = meta_desc['content'] if meta_desc else ''
        
        # Get main content (first few paragraphs)
        main_content = []
        for p in soup.find_all('p')[:5]:  # Get first 5 paragraphs
            text = p.get_text().strip()
            if text and len(text) > 50:  # Only include substantial paragraphs
                main_content.append(text)
        
        content_summary = f"Title: {title}\nDescription: {meta_desc}\nContent: {' '.join(main_content)}"
        
        # Prepare analysis prompt
        prompt = f"""
        Analyze this website content and provide insights in HTML format about:

        Website URL: {url}
        Content: {content_summary[:1500]}  # Limit content for analysis

        Provide analysis in this HTML structure:
        <div class="analysis-container">
            <div class="analysis-section">
                <h3 class="section-title">🎯 Purpose & Legitimacy</h3>
                <ul class="analysis-list">
                    [List key findings about website purpose and legitimacy]
                </ul>
            </div>
            
            <div class="analysis-section">
                <h3 class="section-title">🛡️ Security Assessment</h3>
                <ul class="analysis-list">
                    [List security observations]
                </ul>
            </div>
            
            <div class="analysis-section">
                <h3 class="section-title">⚠️ Potential Red Flags</h3>
                <ul class="analysis-list">
                    [List any concerns or suspicious elements]
                </ul>
            </div>
            
            <div class="analysis-section">
                <h3 class="section-title">💡 Recommendations</h3>
                <ul class="analysis-list">
                    [List recommended actions]
                </ul>
            </div>
        </div>
        """
        
        # Get AI analysis
        completion = groq_client.chat.completions.create(
            model="llama3-70b-8192" , #"llama-3.2-90b-vision-preview",
            messages=[
                {
                    "role": "system", 
                    "content": "You are a cybersecurity expert who provides website analysis in well-structured HTML format with emojis and clear sections."
                },
                {"role": "user", "content": prompt}
            ],
            temperature=1,
            max_tokens=2048
        )
        
        return completion.choices[0].message.content
        
    except Exception as e:
        return f"""
        <div class="error-container">
            <h3 class="error-title">❌ Error Analyzing Content</h3>
            <p class="error-message">{str(e)}</p>
        </div>
        """

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check')
def check():
    return render_template('check.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        url = request.form['url']
        processed_url = preprocess_url(url)
        
        # Get initial prediction
        prediction = predict_url(processed_url)
        
        # Get WHOIS data
        whois_data = fetch_whois_data(processed_url)
        
        # Get content analysis
        insights = scrape_and_analyze_content(processed_url)
        
        return jsonify({
            'prediction': prediction,
            'whois_data': whois_data,
            'insights': insights
        })
        
    except Exception as e:
        return jsonify({
            'error': str(e),
            'message': 'An error occurred while analyzing the URL'
        }), 500
    
@app.route('/flow')
def flow():
    return render_template('flow.html', 
        title='How It Works | URL Security Scanner',
        description='Learn how our URL security scanning process works'
    )

if __name__ == '__main__':
    app.run(debug=True)