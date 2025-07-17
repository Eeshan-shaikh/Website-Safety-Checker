from urllib.parse import urlparse
import numpy as np
import re
from sklearn.linear_model import LogisticRegression
import pickle
import os

model = None
additional_features = {}

class URLSafetyModel:
    @staticmethod
    def load_model():
        global model
        # For demonstration, create a simple logistic regression model trained with synthetic data
        model_path = 'url_safety_model.pkl'
        if os.path.exists(model_path):
            try:
                with open(model_path, 'rb') as f:
                    model = pickle.load(f)
                    print(f"Successfully loaded model from {model_path}")
            except Exception as e:
                print(f"Error loading model: {e}")
                # Fall back to creating a new model
                model = None
        else:
            # Create synthetic data
            # Features: [url_length, has_ip, count_dots, count_hyphens, count_at, count_question, count_equal]
            X = []
            y = []
            safe_urls = [
                'http://example.com',
                'https://openai.com',
                'http://github.com',
                'https://google.com/search?q=test'
            ]
            unsafe_urls = [
                'http://192.168.0.1/evil',
                'http://free-money.com@badsite.com',
                'http://example.com/login?user=test&pass=123',
                'http://phishing-site.com?redirect=http://bad.com'
            ]

            for url in safe_urls:
                features = extract_features(url)
                X.append(features)
                y.append(1)
            for url in unsafe_urls:
                features = extract_features(url)
                X.append(features)
                y.append(0)
            X = np.array(X)
            y = np.array(y)
            clf = LogisticRegression()
            clf.fit(X, y)
            model = clf
            with open('url_safety_model.pkl', 'wb') as f:
                pickle.dump(model, f)

    @staticmethod
    def predict(features):
        global model, additional_features
        
        # Default safe threshold
        safe_threshold = 0.5
        
        # Automatic unsafe classifications regardless of ML model
        if additional_features:
            # Check for brand impersonation - always unsafe
            if additional_features.get('brand_impersonation', {}).get('detected', False):
                return False  # Not safe
            
            # Check for giveaway scams - always unsafe if multiple indicators
            if additional_features.get('giveaway_scam', {}).get('multiple_indicators', False):
                return False  # Not safe
                
            # Check for tech support scams - always unsafe if detected
            if additional_features.get('tech_support_scam', {}).get('detected', False):
                return False  # Not safe
                
            # Check for financial scams - always unsafe if detected
            if additional_features.get('financial_scam', {}).get('detected', False):
                return False  # Not safe
                
            # Check for domain confusion - always unsafe if detected
            if additional_features.get('domain_confusion', {}).get('detected', False):
                return False  # Not safe
        
        # Check model prediction
        if model:
            proba = model.predict_proba([features])[0][1]
            return proba >= safe_threshold
        
        return None

    @staticmethod
    def get_explanation(features):
        # provide simple explanation about features for demo
        explanation = {
            'url_length': features[0],
            'has_ip': bool(features[1]),
            'dot_count': features[2],
            'hyphen_count': features[3],
            'at_count': features[4],
            'question_mark_count': features[5],
            'equal_sign_count': features[6]
        }
        
        # Add threat analysis based on features
        threats = URLSafetyModel.analyze_threats(features, explanation)
        explanation['threats'] = threats
        
        return explanation
        
    @staticmethod
    def analyze_threats(features, explanation):
        """Analyze potential threats based on URL features"""
        global additional_features
        threats = []
        
        # Check for IP-based URL (often used in phishing)
        if explanation['has_ip']:
            threats.append({
                'type': 'IP-based URL',
                'severity': 'High',
                'description': 'URLs containing IP addresses instead of domain names are often associated with phishing attempts.',
                'mitigation': 'Verify the legitimacy of the website through other means before proceeding.'
            })
        
        # Check for excessive dots (domain spoofing)
        if explanation['dot_count'] > 3:
            threats.append({
                'type': 'Domain spoofing',
                'severity': 'Medium',
                'description': 'Multiple dots may indicate an attempt to create a confusing subdomain structure to mimic legitimate domains.',
                'mitigation': 'Check the actual domain name carefully before entering any credentials.'
            })
        
        # Check for @ symbol in URL (used for URL misdirection)
        if explanation['at_count'] > 0:
            threats.append({
                'type': 'URL misdirection',
                'severity': 'High',
                'description': 'The @ symbol in URLs can lead browsers to ignore everything before it, potentially directing to a malicious site.',
                'mitigation': 'Never trust URLs containing @ symbols.'
            })
        
        # Check for excessive parameters (potential data harvesting)
        if explanation['equal_sign_count'] > 3:
            threats.append({
                'type': 'Parameter exploitation',
                'severity': 'Medium',
                'description': 'Excessive URL parameters may indicate an attempt to harvest data or exploit vulnerabilities.',
                'mitigation': 'Be cautious about clicking links with many parameters in the URL.'
            })
        
        # Check for very long URLs (obfuscation technique)
        if explanation['url_length'] > 75:
            threats.append({
                'type': 'URL obfuscation',
                'severity': 'Low',
                'description': 'Unusually long URLs may be attempting to hide malicious destinations or code.',
                'mitigation': 'Hover over links to see their true destination before clicking.'
            })
        
        # Check for excessive hyphens (typosquatting)
        if explanation['hyphen_count'] > 2:
            threats.append({
                'type': 'Typosquatting',
                'severity': 'Medium',
                'description': 'Multiple hyphens may indicate a typosquatting attempt to mimic a legitimate domain.',
                'mitigation': 'Verify the domain name carefully and consider typing it directly in your browser.'
            })
        
        # Additional threat checks using our new features
        if additional_features:
            # Check for redirects in the URL
            if additional_features.get('count_redirects', 0) > 0:
                threats.append({
                    'type': 'Redirection Chain',
                    'severity': 'High',
                    'description': 'This URL contains redirection parameters that may lead you to a different site than what appears in the link.',
                    'mitigation': 'Avoid clicking URLs with redirection parameters or copy the base URL directly.'
                })
            
            # Check for lack of HTTPS (transport security)
            if not additional_features.get('has_https', 0):
                threats.append({
                    'type': 'Insecure Connection',
                    'severity': 'Medium',
                    'description': 'This URL uses HTTP instead of HTTPS, meaning your connection is not encrypted and could be intercepted.',
                    'mitigation': 'Only enter sensitive information on websites using HTTPS connections.'
                })
            
            # Check for excessive digits in the domain (suspicious)
            if additional_features.get('count_digits', 0) > 5:
                threats.append({
                    'type': 'Suspicious Domain Pattern',
                    'severity': 'Medium',
                    'description': 'Domains with excessive numerical characters are often algorithmically generated for malicious purposes.',
                    'mitigation': 'Be wary of domains that contain many numbers in their name.'
                })
            
            # Check for suspicious words in the URL
            if additional_features.get('count_suspicious_words', 0) > 0:
                threats.append({
                    'type': 'Suspicious Terminology',
                    'severity': 'Medium',
                    'description': 'This URL contains words commonly used in phishing attempts such as "login", "secure", "account", etc.',
                    'mitigation': 'Be wary of URLs that use terminology related to security, accounts, or banking services.'
                })
                
            # Check for brand impersonation (character substitution, typosquatting)
            if additional_features.get('brand_impersonation', {}).get('detected', False):
                brand_info = additional_features.get('brand_impersonation', {})
                brand_name = brand_info.get('brand', 'a popular brand')
                impersonation_type = brand_info.get('type', '')
                
                threats.append({
                    'type': 'Brand Impersonation Attack',
                    'severity': 'High',
                    'description': f'This URL appears to be impersonating {brand_name.title()} using character substitution or misspelling ({impersonation_type}). This is a common phishing technique.',
                    'mitigation': f'This is not an official {brand_name.title()} website. Always check for the correct spelling of domain names of popular services.'
                })
            
            # Check for suspicious TLD (Top Level Domain)
            if additional_features.get('has_suspicious_tld', 0):
                threats.append({
                    'type': 'Suspicious Domain Extension',
                    'severity': 'Medium', 
                    'description': 'This URL uses a top-level domain that is commonly associated with malicious websites.',
                    'mitigation': 'Exercise caution with websites using uncommon or free top-level domains.'
                })
            
            # Check for excessive subdomains
            if additional_features.get('count_subdomains', 0) > 2:
                threats.append({
                    'type': 'Subdomain Abuse',
                    'severity': 'Medium',
                    'description': 'Excessive subdomains may be an attempt to make a malicious URL appear legitimate or to evade detection.',
                    'mitigation': 'Check the second-level domain (the part before the TLD) to verify the true domain owner.'
                })
                
            # Check for excessively long path
            if additional_features.get('path_length', 0) > 50:
                threats.append({
                    'type': 'Path Obfuscation',
                    'severity': 'Low',
                    'description': 'The unusually long path in this URL may be an attempt to hide malicious code or confuse security filters.',
                    'mitigation': 'Be cautious of URLs with extremely long and complex paths.'
                })
                
            # Check for giveaway/prize scam indicators
            giveaway_info = additional_features.get('giveaway_scam', {})
            if giveaway_info.get('detected', False):
                # If multiple indicators were found, it's more likely to be a scam
                severity = 'High' if giveaway_info.get('multiple_indicators', False) else 'Medium'
                words_found = giveaway_info.get('words_found', [])
                words_str = ', '.join([f'"{word}"' for word in words_found[:3]])
                if len(words_found) > 3:
                    words_str += f', and {len(words_found) - 3} more'
                
                threats.append({
                    'type': 'Giveaway/Prize Scam',
                    'severity': severity,
                    'description': f'This URL contains terms commonly associated with fake giveaways and prize scams ({words_str}). These often lead to phishing, malware, or subscription traps.',
                    'mitigation': 'Be extremely cautious of "free" offers. Legitimate companies rarely give away expensive products for free online.'
                })
                
            # Check for tech support scam indicators
            tech_support_info = additional_features.get('tech_support_scam', {})
            if tech_support_info.get('detected', False):
                words_found = tech_support_info.get('words_found', [])
                words_str = ', '.join([f'"{word}"' for word in words_found[:3]])
                if len(words_found) > 3:
                    words_str += f', and {len(words_found) - 3} more'
                
                threats.append({
                    'type': 'Tech Support Scam',
                    'severity': 'High',
                    'description': f'This URL appears to be a tech support scam ({words_str}). These sites often display fake virus warnings and urge you to call a phone number where scammers will request payment or remote access to your device.',
                    'mitigation': 'Never call phone numbers from pop-up warnings. Legitimate tech companies like Microsoft or Apple never display such warnings in your browser.'
                })
                
            # Check for financial/banking scam indicators
            financial_info = additional_features.get('financial_scam', {})
            if financial_info.get('detected', False):
                words_found = financial_info.get('words_found', [])
                words_str = ', '.join([f'"{word}"' for word in words_found[:3]])
                if len(words_found) > 3:
                    words_str += f', and {len(words_found) - 3} more'
                
                threats.append({
                    'type': 'Financial Phishing Attempt',
                    'severity': 'High',
                    'description': f'This URL contains terms associated with banking or financial services ({words_str}). It appears to be attempting to collect your financial information.',
                    'mitigation': 'Always access your bank directly by typing the official URL. Banks never send emails asking you to "verify" or "update" your account information.'
                })
                
            # Check for domain confusion/misdirection
            domain_confusion_info = additional_features.get('domain_confusion', {})
            if domain_confusion_info.get('detected', False):
                brand = domain_confusion_info.get('brand', 'a popular brand')
                position = domain_confusion_info.get('position', 'subdomain')
                
                position_explanation = ""
                if position == "subdomain":
                    position_explanation = f"The {brand} name appears as a subdomain, not the main domain."
                else:
                    position_explanation = f"The {brand} name appears in the domain but is not the official domain."
                
                threats.append({
                    'type': 'Domain Confusion Attack',
                    'severity': 'High',
                    'description': f'This URL is using domain confusion to impersonate {brand}. {position_explanation} This is a common phishing technique to make malicious URLs look legitimate.',
                    'mitigation': f'The official {brand} website would be at "{brand}.com". Always check the main domain name (the part before the TLD) to verify you are on the official site.'
                })
        
        return threats

def extract_features(url):
    """
    Extract features from a URL for use in the machine learning model
    and detailed threat analysis.
    
    Args:
        url (str): The URL to analyze
    
    Returns:
        list: A list of numerical features for model prediction
    """
    # Basic features from URL for demonstration
    parsed = urlparse(url)
    url_str = url.lower()
    url_length = len(url_str)

    # Check if hostname is an IP address
    hostname = parsed.hostname if parsed.hostname else ''
    has_ip = int(bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname)))

    # Additional feature extractions
    count_dots = url_str.count('.')
    count_hyphens = url_str.count('-')
    count_at = url_str.count('@')
    count_question = url_str.count('?')
    count_equal = url_str.count('=')
    
    # Additional features for deeper analysis (not used in current model but used in threat analysis)
    count_redirects = url_str.count('redirect') + url_str.count('redir') + url_str.count('url=')
    has_https = 1 if url_str.startswith('https://') else 0
    count_digits = sum(c.isdigit() for c in url_str)
    
    # Check for suspicious words in the URL
    suspicious_words = ['secure', 'account', 'webscr', 'login', 'ebay', 'paypal', 'signin', 'banking', 'confirm']
    count_suspicious_words = sum(1 for word in suspicious_words if word in url_str)
    
    # Check for scam/giveaway phrases
    scam_giveaway_phrases = [
        'free', 'win', 'winner', 'prize', 'reward', 'gift', 'claim',
        'iphone', 'samsung', 'playstation', 'xbox', 'nintendo', 'ipad',
        'macbook', 'laptop', 'airpods', 'discount', 'promo', 'limited',
        'offer', 'chance', 'lottery', 'lucky', 'congratulation'
    ]
    
    # Check for tech support scam keywords
    tech_support_scam_phrases = [
        'security-alert', 'security-warning', 'alert', 'warning', 'error',
        'virus', 'malware', 'infected', 'call-now', 'support', 'microsoft-support',
        'apple-support', 'helpdesk', 'help-desk', 'technical', 'windows-security'
    ]
    
    # Check for banking and financial scam phrases
    financial_scam_phrases = [
        'verify', 'update-info', 'update-account', 'confirm-identity', 'bank',
        'banking', 'account-update', 'security-update', 'secure-login', 'chase',
        'wellsfargo', 'bankofamerica', 'citibank', 'hsbc', 'barclays', 'santander',
        'creditcard', 'credit-card', 'billing', 'payment'
    ]
    # Detect giveaway scams
    has_giveaway_scam_words = False
    giveaway_scam_words_found = []
    
    for word in scam_giveaway_phrases:
        if word in url_str:
            has_giveaway_scam_words = True
            giveaway_scam_words_found.append(word)
            
    count_giveaway_scam_words = len(giveaway_scam_words_found)
    has_multiple_giveaway_indicators = count_giveaway_scam_words >= 2
    
    # Detect tech support scams
    has_tech_support_scam_words = False
    tech_support_scam_words_found = []
    
    for word in tech_support_scam_phrases:
        if word in url_str:
            has_tech_support_scam_words = True
            tech_support_scam_words_found.append(word)
    
    count_tech_support_scam_words = len(tech_support_scam_words_found)
    has_multiple_tech_support_indicators = count_tech_support_scam_words >= 1
    
    # Detect financial/banking scams
    has_financial_scam_words = False
    financial_scam_words_found = []
    
    for word in financial_scam_phrases:
        if word in url_str:
            has_financial_scam_words = True
            financial_scam_words_found.append(word)
    
    count_financial_scam_words = len(financial_scam_words_found)
    has_multiple_financial_indicators = count_financial_scam_words >= 1
    
    # Detect domain confusion/misdirection (e.g., legitimate-brand.malicious.com)
    # This is a common phishing technique where trusted brands appear in subdomains
    confused_domain = False
    domain_parts = hostname.split('.')
    
    # Popular domains that attackers try to confuse users with
    popular_brands = ['apple', 'microsoft', 'amazon', 'google', 'facebook', 'paypal', 
                      'netflix', 'linkedin', 'twitter', 'instagram', 'bankofamerica', 
                      'chase', 'wellsfargo', 'citibank', 'amex', 'mastercard', 'visa']
    
    confused_brand = None
    domain_position = "subdomain"  # Can be "subdomain" or "not_main_domain"
    
    # Brand appears in subdomain but not as the main domain
    for brand in popular_brands:
        # Check if brand is in the hostname but is not the main domain
        if brand in hostname:
            main_domain_parts = domain_parts[-2] if len(domain_parts) > 1 else ''
            if brand not in main_domain_parts:
                confused_domain = True
                confused_brand = brand
                
                # If the brand is not the second-level domain
                if len(domain_parts) >= 2 and brand not in domain_parts[-2]:
                    domain_position = "subdomain"
                # If brand appears in second-level domain but with additions
                elif len(domain_parts) >= 2 and brand in domain_parts[-2] and brand != domain_parts[-2]:
                    domain_position = "not_main_domain"
                break
    
    # Path analysis
    path_length = len(parsed.path) if parsed.path else 0
    domain_length = len(hostname)
    count_subdomains = hostname.count('.') if hostname else 0
    has_suspicious_tld = 1 if any(hostname.endswith(tld) for tld in ['.zip', '.tk', '.top', '.xyz', '.ml']) else 0
    
    # Brand impersonation detection
    popular_brands = {
        'facebook': ['facebook', 'faceb00k', 'face-book', 'facbook', 'facebooc', 'facebok', 'facabbok', 'fb-login'],
        'instagram': ['instagram', 'insta-gram', '1nstagram', 'lnstagram'],  # Using l instead of i
        'amazon': ['amazon', 'am4zon', 'amazn', 'amazom', 'anazon'],
        'apple': ['apple', 'appl', 'aple', '4pple', 'app1e'],  # Using 1 instead of l
        'microsoft': ['microsoft', 'micr0soft', 'micro-soft', 'microsfot'],
        'netflix': ['netflix', 'netfl1x', 'net-flix', 'netfllx', 'netf1ix'],
        'paypal': ['paypal', 'payp4l', 'pay-pal', 'paypaI', 'paypai'],  # Using I instead of l
        'google': ['google', 'g00gle', 'go0gle', 'googl', 'googie'],  # Using i instead of l
        'yahoo': ['yahoo', 'yah00', 'yah0o', 'yahho'],
        'twitter': ['twitter', 'tw1tter', 'twltter']  # Using l instead of i
    }
    
    brand_impersonation_detected = False
    impersonated_brand = None
    impersonation_type = None
    
    # Check for brand impersonation
    for brand, variations in popular_brands.items():
        # Skip if this is actually the legitimate domain
        if hostname == f"{brand}.com" or hostname == f"www.{brand}.com":
            continue
            
        for variation in variations:
            # Check for the variation in the hostname, but only if it's not a legitimate domain
            if variation in hostname and variation != brand:
                # Make sure we don't flag legitimate domains
                legitimate_domains = [
                    f"{brand}.com",
                    f"www.{brand}.com",
                    f"{variation}.com",
                    f"www.{variation}.com"
                ]
                
                if hostname not in legitimate_domains:
                    brand_impersonation_detected = True
                    impersonated_brand = brand
                    impersonation_type = f"{brand} → {variation}"
                    break
                    
        if brand_impersonation_detected:
            break
    
    # Store these additional features as global variables for threat analysis
    global additional_features
    additional_features = {
        'count_redirects': count_redirects,
        'has_https': has_https,
        'count_digits': count_digits,
        'count_suspicious_words': count_suspicious_words,
        'path_length': path_length, 
        'domain_length': domain_length,
        'count_subdomains': count_subdomains,
        'has_suspicious_tld': has_suspicious_tld,
        'hostname': hostname,
        'brand_impersonation': {
            'detected': brand_impersonation_detected,
            'brand': impersonated_brand,
            'type': impersonation_type
        },
        'giveaway_scam': {
            'detected': has_giveaway_scam_words,
            'multiple_indicators': has_multiple_giveaway_indicators,
            'words_found': giveaway_scam_words_found,
            'count': count_giveaway_scam_words
        },
        'tech_support_scam': {
            'detected': has_tech_support_scam_words,
            'multiple_indicators': has_multiple_tech_support_indicators,
            'words_found': tech_support_scam_words_found,
            'count': count_tech_support_scam_words
        },
        'financial_scam': {
            'detected': has_financial_scam_words,
            'multiple_indicators': has_multiple_financial_indicators,
            'words_found': financial_scam_words_found,
            'count': count_financial_scam_words
        },
        'domain_confusion': {
            'detected': confused_domain,
            'brand': confused_brand,
            'position': domain_position
        }
    }
    
    # For now, we'll return the original features used to train the model
    return [url_length, has_ip, count_dots, count_hyphens, count_at, count_question, count_equal]
