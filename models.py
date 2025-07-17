from urllib.parse import urlparse
import numpy as np
import re
from sklearn.linear_model import LogisticRegression
import pickle
import os
import tldextract

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
        
        # Default safe threshold - more aggressive (higher threshold means less URLs classified as safe)
        safe_threshold = 0.7  # Increased from 0.5
        
        # Initialize reputation score
        reputation_score = 90  # Start with slightly lower score to be more cautious
        threat_level = "Low"
        
        # Track if we should automatically mark as unsafe regardless of model
        auto_unsafe = False
        
        # Automatic unsafe classifications regardless of ML model
        if additional_features:
            # Check for brand impersonation - always unsafe
            if additional_features.get('brand_impersonation', {}).get('detected', False):
                reputation_score -= 60
                threat_level = "Critical"
                auto_unsafe = True
            
            # Check for giveaway scams - always unsafe if multiple indicators
            if additional_features.get('giveaway_scam', {}).get('multiple_indicators', False):
                reputation_score -= 50
                threat_level = "High"
                auto_unsafe = True
                
            # Check for tech support scams - always unsafe if detected
            if additional_features.get('tech_support_scam', {}).get('detected', False):
                reputation_score -= 55
                threat_level = "High"
                auto_unsafe = True
                
            # Check for financial scams - always unsafe if detected
            if additional_features.get('financial_scam', {}).get('detected', False):
                reputation_score -= 55
                threat_level = "High"
                auto_unsafe = True
                
            # Check category (from the newly added categorize_url function)
            category = additional_features.get('category', {})
            if category:
                category_name = category.get('name', 'Legitimate')
                category_confidence = category.get('confidence', 0.0)
                risk_level = category.get('risk_level', 0)
                
                # If categorized as any security threat, treat more seriously
                if category_name != 'Legitimate':
                    confidence_penalty = int(category_confidence * 50)  # Up to 50 points based on confidence
                    risk_penalty = risk_level * 10  # Up to 50 points for risk level 5
                    
                    reputation_score -= (confidence_penalty + risk_penalty)
                    
                    # Automatically set auto_unsafe for higher confidence threat detections
                    if category_confidence > 0.5 or risk_level >= 3:
                        auto_unsafe = True
                        
                    # Set threat level based on category
                    if category_name == 'Malware' or category_name == 'Phishing':
                        threat_level = "Critical"
                    elif category_name == 'Defacement':
                        threat_level = "High"
                    elif category_name == 'Suspicious':
                        threat_level = "Medium"
                    elif category_name == 'Spam':
                        threat_level = "Medium"
                
            # Check for domain confusion - always unsafe if detected
            if additional_features.get('domain_confusion', {}).get('detected', False):
                reputation_score -= 45
                threat_level = "High"
                auto_unsafe = True
                
            # Check for excessive URL length - likely unsafe
            if additional_features.get('url_length', 0) > 200:
                reputation_score -= 25
                if threat_level == "Low":
                    threat_level = "Medium"
                if additional_features.get('url_length', 0) > 300:
                    auto_unsafe = True
                
            # Check for credential stealing attempt
            if additional_features.get('credential_stealing', {}).get('detected', False):
                reputation_score -= 60
                threat_level = "Critical"
                auto_unsafe = True
                
            # Check for high-risk TLD
            if additional_features.get('high_risk_tld', False):
                reputation_score -= 30
                if threat_level == "Low":
                    threat_level = "Medium"
                auto_unsafe = True
                
            # Smaller penalties for other suspicious features
            if additional_features.get('has_ip', False):
                reputation_score -= 20
                if threat_level == "Low":
                    threat_level = "Medium"
                
            if additional_features.get('count_suspicious_words', 0) > 0:
                reputation_score -= 5 * min(additional_features.get('count_suspicious_words', 0), 5)
                
            if additional_features.get('count_redirects', 0) > 0:
                reputation_score -= 10 * min(additional_features.get('count_redirects', 0), 3)
                
            if not additional_features.get('has_https', False):
                reputation_score -= 15
                
            if additional_features.get('count_digits', 0) > 5:
                reputation_score -= 15
                
            if additional_features.get('has_suspicious_tld', False):
                reputation_score -= 20
                
            if additional_features.get('count_subdomains', 0) > 2:
                reputation_score -= 5 * min(additional_features.get('count_subdomains', 0) - 2, 4)
        
        # Add the reputation score and threat level to additional_features for display
        additional_features['reputation_score'] = max(0, reputation_score)
        additional_features['threat_level'] = threat_level
        
        # If we have an automatic unsafe classification, return immediately
        if auto_unsafe:
            return False  # Not safe
        
        # Check model prediction if no automatic classification
        if model:
            proba = model.predict_proba([features])[0][1]
            
            # Much more aggressive threshold - harder to classify as safe
            is_safe = proba >= safe_threshold
            
            # Additional check for typosquatting or suspicious spellings
            if 'typosquatting' not in additional_features:
                additional_features['typosquatting'] = {'detected': False, 'score': 0}
                # Check URL for common domain typos and misspellings
                typo_score = check_for_typosquatting(features)
                if typo_score > 0:
                    additional_features['typosquatting'] = {
                        'detected': True,
                        'score': typo_score
                    }
                    # Higher typo score means higher chance of being a dangerous lookalike site
                    reputation_score -= typo_score * 15
                    # Force unsafe for high typo scores
                    if typo_score >= 3:
                        is_safe = False
                        
            # Adjust reputation score based on model probability
            if is_safe:
                # Even for safe URLs, if probability is close to threshold, reduce score significantly
                if proba < 0.8:  # Increased from 0.7
                    reputation_score -= 30 * (0.8 - proba)  # Increased penalty from 20 to 30
                    if reputation_score < 75 and threat_level == "Low":  # Increased threshold from 70 to 75
                        additional_features['threat_level'] = "Medium"
            else:
                # For unsafe URLs, further reduce score more aggressively
                reputation_score -= 40 * (1 - proba)  # Increased from 30 to 40
                if threat_level == "Low":
                    additional_features['threat_level'] = "Medium"
                
            # If reputation score is very low, override to unsafe classification
            if reputation_score < 50:  # More aggressive cutoff, was not present before
                is_safe = False
                    
            # Update the final reputation score
            additional_features['reputation_score'] = max(0, int(reputation_score))
            
            return is_safe
        
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
                    'description': f'This URL contains language commonly associated with fake giveaways or prize scams ({words_str}). These are typically used to collect personal information or install malware.',
                    'mitigation': 'Be extremely cautious of websites offering free prizes, giveaways, or rewards. Legitimate companies rarely give away products for free without clear terms and conditions.'
                })
                
            # Check for tech support scam indicators
            tech_support_info = additional_features.get('tech_support_scam', {})
            if tech_support_info.get('detected', False):
                threats.append({
                    'type': 'Tech Support Scam',
                    'severity': 'High',
                    'description': 'This URL appears to be associated with fake tech support scams that try to convince users they have technical problems to extract payment or install malware.',
                    'mitigation': 'Never call tech support numbers from suspicious websites. Contact companies directly through their official websites if you need assistance.'
                })
                
            # Check for financial scam indicators
            financial_info = additional_features.get('financial_scam', {})
            if financial_info.get('detected', False):
                threats.append({
                    'type': 'Financial Scam',
                    'severity': 'High',
                    'description': 'This URL contains patterns associated with financial scams, such as fake investments, cryptocurrency scams, or get-rich-quick schemes.',
                    'mitigation': 'Never trust unrealistic financial offers. Legitimate investment opportunities don\'t promise guaranteed high returns with no risk.'
                })
                
            # Check for domain name confusion (IDN homograph attack)
            domain_confusion = additional_features.get('domain_confusion', {})
            if domain_confusion.get('detected', False):
                confused_domain = domain_confusion.get('similar_to', 'a legitimate domain')
                threats.append({
                    'type': 'Homograph Attack',
                    'severity': 'High',
                    'description': f'This URL uses characters that look similar to those in {confused_domain} but are actually different. This is a sophisticated phishing technique.',
                    'mitigation': 'Always check the URL carefully, especially when entering sensitive information. Consider typing the URL directly rather than clicking links.'
                })
                
            # Check for credential stealing indicators
            credential_info = additional_features.get('credential_stealing', {})
            if credential_info.get('detected', False):
                threats.append({
                    'type': 'Credential Harvesting',
                    'severity': 'High',
                    'description': 'This URL contains patterns associated with credential theft, designed to trick users into entering their login information.',
                    'mitigation': 'Never enter login credentials on sites reached through email links or pop-ups. Go directly to the official website instead.'
                })
                
            # Check for high-risk TLD
            if additional_features.get('high_risk_tld', False):
                threats.append({
                    'type': 'High-Risk Domain Extension',
                    'severity': 'High',
                    'description': 'This URL uses a top-level domain that is frequently associated with malicious activity and scams.',
                    'mitigation': 'Be extremely cautious with websites using this domain extension, especially when sharing personal information.'
                })
        
        return threats

def check_for_typosquatting(features):
    """
    Check for common typosquatting techniques in a URL
    Returns a score from 0-5 indicating likelihood of typosquatting
    """
    global additional_features
    
    # Need the original URL to check
    if 'original_url' not in additional_features:
        return 0
    
    url = additional_features['original_url']
    parsed_url = urlparse(url)
    netloc = parsed_url.netloc.lower()
    
    # Common legitimate domains that are frequently impersonated
    legitimate_domains = [
        'google', 'facebook', 'apple', 'microsoft', 'amazon', 'netflix', 'paypal',
        'instagram', 'twitter', 'linkedin', 'youtube', 'github', 'gmail', 'yahoo',
        'outlook', 'dropbox', 'chase', 'bankofamerica', 'wellsfargo', 'citibank',
        'amex', 'walmart', 'target', 'ebay', 'coinbase', 'binance'
    ]
    
    # Check for typosquatting techniques
    
    # 1. Character substitution (e.g., '0' for 'o', '1' for 'l')
    substitutions = [
        ('o', '0'), ('l', '1'), ('i', '1'), ('e', '3'), ('a', '4'),
        ('s', '5'), ('b', '8'), ('g', '9'), ('m', 'rn'), ('w', 'vv')
    ]
    
    # 2. Character omission (e.g., 'goggle' vs 'google')
    # 3. Character addition (e.g., 'gooogle' vs 'google')
    # 4. Character replacement (e.g., 'goofle' vs 'google')
    # 5. Character transposition (e.g., 'googel' vs 'google')
    
    # Check if the domain is a typosquatting variant of a legitimate domain
    typo_score = 0
    matched_domains = []
    
    # Remove 'www.' if present
    if netloc.startswith('www.'):
        netloc = netloc[4:]
    
    # Remove TLD for comparison (e.g., '.com', '.org')
    domain = netloc.split('.')[0] if netloc and '.' in netloc else netloc
    
    for legit_domain in legitimate_domains:
        # Check for character substitution
        for original, substitute in substitutions:
            if original in legit_domain:
                variant = legit_domain.replace(original, substitute)
                if variant == domain or variant in domain:
                    typo_score += 2
                    matched_domains.append(legit_domain)
                    break
        
        # Check for minor misspellings (edit distance of 1 or 2)
        import editdistance
        ed = editdistance.eval(legit_domain, domain)
        if 0 < ed <= 2 and len(legit_domain) > 4:  # Only for domains longer than 4 chars
            typo_score += 3
            matched_domains.append(legit_domain)
        
        # Check for character addition (inserting 1-2 chars)
        if len(domain) > len(legit_domain) and len(domain) - len(legit_domain) <= 2:
            if legit_domain in domain:
                typo_score += 2
                matched_domains.append(legit_domain)
    
    # Check for suspicious TLDs used in phishing
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz', '.info']
    for tld in suspicious_tlds:
        if netloc.endswith(tld):
            typo_score += 1
            break
    
    # Cap the score at 5
    typo_score = min(typo_score, 5)
    
    # If we found typosquatting, save the matched domains
    if typo_score > 0:
        additional_features['typosquatting_matches'] = matched_domains
    
    return typo_score

def extract_features(url):
    """Extract features from a URL for safety analysis"""
    global additional_features
    
    # Reset additional features dictionary for this new URL
    additional_features = {}
    additional_features['original_url'] = url
    
    # Parse the URL
    parsed_url = urlparse(url)
    
    # Feature 1: URL Length
    url_length = len(url)
    additional_features['url_length'] = url_length
    
    # Feature 2: Presence of IP address
    has_ip = 1 if bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', parsed_url.netloc)) else 0
    
    # Feature 3: Count of dots in URL
    count_dots = url.count('.')
    
    # Feature 4: Count of hyphens in URL
    count_hyphens = url.count('-')
    
    # Feature 5: Count of @ symbols in URL
    count_at = url.count('@')
    
    # Feature 6: Count of question marks in URL
    count_question = url.count('?')
    
    # Feature 7: Count of equal signs in URL (parameters)
    count_equal = url.count('=')
    
    # Compile the basic feature vector
    features = [url_length, has_ip, count_dots, count_hyphens, count_at, count_question, count_equal]
    
    # Additional features for enhanced detection
    
    # HTTPS usage
    additional_features['has_https'] = parsed_url.scheme == 'https'
    
    # Perform URL categorization
    try:
        categorize_url(url, parsed_url)
    except Exception as e:
        print(f"Error in URL categorization: {e}")
        # Initialize with safe defaults if categorization fails
        additional_features['category'] = {
            "id": None, 
            "name": "Legitimate", 
            "confidence": 0.7, 
            "risk_level": 0
        }
    
    # Domain information
    extract_result = tldextract.extract(url)
    domain = extract_result.domain
    tld = extract_result.suffix
    subdomain = extract_result.subdomain
    
    # Count of digits in domain
    count_digits = sum(c.isdigit() for c in domain)
    additional_features['count_digits'] = count_digits
    
    # Count of subdomains
    count_subdomains = len(subdomain.split('.')) if subdomain else 0
    additional_features['count_subdomains'] = count_subdomains
    
    # Path length
    path_length = len(parsed_url.path)
    additional_features['path_length'] = path_length
    
    # Suspicious TLDs (commonly associated with malicious sites)
    suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'date', 'win', 'review', 'country']
    additional_features['has_suspicious_tld'] = tld in suspicious_tlds
    
    # High-risk TLDs (extremely high correlation with malicious activity)
    high_risk_tlds = ['zip', 'racing', 'party', 'stream', 'casa', 'icu', 'online', 'support']
    additional_features['high_risk_tld'] = tld in high_risk_tlds
    
    # Suspicious words in URL (common in phishing)
    suspicious_words = ['login', 'signin', 'verify', 'bank', 'account', 'update', 'secure', 'security',
                      'paypal', 'password', 'credential', 'confirm', 'apple', 'microsoft', 'payment']
    
    url_lower = url.lower()
    found_suspicious_words = [word for word in suspicious_words if word in url_lower]
    additional_features['count_suspicious_words'] = len(found_suspicious_words)
    if found_suspicious_words:
        additional_features['suspicious_words_found'] = found_suspicious_words
    
    # Check for redirection parameters
    redirect_params = ['redirect', 'redir', 'url', 'link', 'goto', 'return', 'returnurl', 'redirecturl', 'continue']
    count_redirects = sum(1 for param in redirect_params if param in parsed_url.query.lower())
    additional_features['count_redirects'] = count_redirects
    
    # Check for brand impersonation (simple implementation)
    popular_brands = ['google', 'facebook', 'apple', 'microsoft', 'amazon', 'netflix', 'paypal', 'instagram', 'twitter']
    
    full_domain = f"{subdomain}.{domain}".strip(".") if subdomain else domain
    
    # Check for brand impersonation with slight variations
    for brand in popular_brands:
        # Check for brand in domain but not exact match (potential typosquatting)
        if brand in full_domain and brand != full_domain:
            # Check for character substitution (e.g., 0 for o, 1 for l)
            typo_indicators = {
                'o': '0', 'l': '1', 'i': '1', 'e': '3', 'a': '4', 's': '5', 'b': '8',
                '0': 'o', '1': 'l', '1': 'i', '3': 'e', '4': 'a', '5': 's', '8': 'b'
            }
            
            # Check if brand name is present with character substitution
            has_typo_brand = False
            impersonation_type = ""
            
            # Check for character substitution
            brand_chars = list(brand)
            for i, char in enumerate(brand_chars):
                if char in typo_indicators:
                    test_brand = brand[:i] + typo_indicators[char] + brand[i+1:]
                    if test_brand in full_domain:
                        has_typo_brand = True
                        impersonation_type = "character substitution"
                        break
            
            # Check for additional characters in brand name
            if brand + "secure" in full_domain or brand + "login" in full_domain:
                has_typo_brand = True
                impersonation_type = "suffix addition"
            
            # Check for misspellings (drop a character)
            for i in range(len(brand)):
                misspelled = brand[:i] + brand[i+1:]
                if len(misspelled) > 3 and misspelled in full_domain:
                    has_typo_brand = True
                    impersonation_type = "character omission"
                    break
            
            # Check for adjacent key typos (simplified)
            keyboard_adjacency = {
                'a': ['s', 'w', 'q'], 'b': ['v', 'n', 'g'], 'c': ['x', 'v', 'd'], 'd': ['s', 'f', 'e'],
                'e': ['w', 'r', 'd'], 'f': ['d', 'g', 'r'], 'g': ['f', 'h', 't'], 'h': ['g', 'j', 'y'],
                'i': ['u', 'o', 'k'], 'j': ['h', 'k', 'u'], 'k': ['j', 'l', 'i'], 'l': ['k', ';', 'o'],
                'm': ['n', ',', 'j'], 'n': ['b', 'm', 'h'], 'o': ['i', 'p', 'l'], 'p': ['o', '[', ';'],
                'q': ['a', 'w', '1'], 'r': ['e', 't', 'f'], 's': ['a', 'd', 'w'], 't': ['r', 'y', 'g'],
                'u': ['y', 'i', 'j'], 'v': ['c', 'b', 'g'], 'w': ['q', 'e', 's'], 'x': ['z', 'c', 's'],
                'y': ['t', 'u', 'h'], 'z': ['x', 'c', 'a']
            }
            
            for i, char in enumerate(brand):
                if char in keyboard_adjacency:
                    for adjacent_key in keyboard_adjacency[char]:
                        typo_brand = brand[:i] + adjacent_key + brand[i+1:]
                        if typo_brand in full_domain:
                            has_typo_brand = True
                            impersonation_type = "keyboard proximity typo"
                            break
                    if has_typo_brand:
                        break
            
            if has_typo_brand:
                additional_features['brand_impersonation'] = {
                    'detected': True,
                    'brand': brand,
                    'type': impersonation_type,
                    'domain': full_domain
                }
                break
    
    # Check for giveaway scam patterns
    giveaway_words = ['free', 'win', 'winner', 'won', 'prize', 'claim', 'reward', 'gift', 'giveaway', 
                       'congratulations', 'congrats', 'lucky', 'selected', 'lottery', 'bonus']
    
    found_giveaway_words = [word for word in giveaway_words if word in url_lower]
    
    if found_giveaway_words:
        additional_features['giveaway_scam'] = {
            'detected': True,
            'words_found': found_giveaway_words,
            'multiple_indicators': len(found_giveaway_words) >= 2
        }
    
    # Check for tech support scam patterns
    tech_support_words = ['support', 'help', 'virus', 'error', 'problem', 'fix', 'alert', 'warning', 
                           'detected', 'security', 'scan', 'damage', 'hacked', 'call']
    
    found_tech_words = [word for word in tech_support_words if word in url_lower]
    
    if len(found_tech_words) >= 3:  # Multiple tech support keywords needed for detection
        additional_features['tech_support_scam'] = {
            'detected': True,
            'words_found': found_tech_words
        }
    
    # Check for financial scam patterns
    financial_words = ['bitcoin', 'crypto', 'invest', 'forex', 'profit', 'rich', 'money', 'trading', 
                        'income', 'earn', 'cash', 'millionaire', 'wealth', 'trader', 'investment']
    
    found_financial_words = [word for word in financial_words if word in url_lower]
    
    if len(found_financial_words) >= 2:  # Multiple financial keywords needed for detection
        additional_features['financial_scam'] = {
            'detected': True,
            'words_found': found_financial_words
        }
    
    # Check for credential stealing
    credential_words = ['log-in', 'signin', 'username', 'password', 'ssn', 'verification', 'verify',
                         'authenticate', 'authorize', 'restore', 'limited', 'locked', 'access', 'billing']
    
    found_credential_words = [word for word in credential_words if word in url_lower]
    
    if len(found_credential_words) >= 2:
        additional_features['credential_stealing'] = {
            'detected': True,
            'words_found': found_credential_words
        }
    
    return features

def categorize_url(url, parsed_url=None):
    """Categorize the URL based on security threat indicators"""
    global additional_features
    
    if parsed_url is None:
        parsed_url = urlparse(url)
    
    # Extract the domain without TLD using tldextract
    try:
        import tldextract
        ext = tldextract.extract(url)
        domain = ext.domain
        suffix = ext.suffix
        subdomain = ext.subdomain
        full_domain = ext.registered_domain
    except:
        # Fallback if tldextract fails
        domain = parsed_url.netloc.split('.')[-2] if len(parsed_url.netloc.split('.')) > 1 else parsed_url.netloc
        full_domain = parsed_url.netloc
    
    # Initialize the categorization result - default to not a threat
    category = {"id": None, "name": "Legitimate", "confidence": 0.7, "risk_level": 0}
    
    # Keywords associated with each threat category
    threat_keywords = {
        "Suspicious": [
            "login", "signin", "verify", "password", "credential", "token", "update", "urgent", "unusual",
            "confirm", "secure", "validate", "alert", "attention", "important", "required", "action",
            "random", "strange", "redirect", "unusual", "suspicious", "warning", "notification"
        ],
        "Spam": [
            "free", "offer", "deal", "discount", "prize", "winner", "buy", "cash", "earn", "money",
            "click", "cheap", "limited", "bargain", "sale", "promo", "viagra", "pharmacy", "pill",
            "weight", "diet", "income", "rich", "casino", "lottery", "subscribe", "unsubscribe"
        ],
        "Phishing": [
            "account", "verify", "confirm", "login", "update", "secure", "banking", "paypal", "apple",
            "microsoft", "google", "amazon", "netflix", "bank", "suspended", "limited", "access",
            "security", "password", "credential", "verification", "validate", "ebay", "facebook",
            "instagram", "twitter", "signin", "recovery", "unlock", "authenticate", "blockchain"
        ],
        "Malware": [
            "download", "exe", "install", "update", "flash", "adobe", "java", "plugin", "codec",
            "crack", "keygen", "serial", "warez", "free-download", "install", "setup", "patch",
            "hack", "cheat", "generator", "activator", "attachment", "driver", "trojan", "virus"
        ],
        "Defacement": [
            "hacked", "owned", "pwned", "defaced", "hacker", "hacktivist", "anonymous", "cyber",
            "leaked", "breached", "compromised", "takeover", "unauthorized", "modified", "altered",
            "vandalized", "graffiti", "political", "protest", "anarchy", "chaos", "rebellion"
        ]
    }
    
    # URL patterns associated with each threat type
    suspicious_patterns = [
        r'(\d{1,3}\.){3}\d{1,3}',             # IP address in URL
        r'(https?|http).*\d+\.\d+\.\d+\.\d+',  # IP with http(s)
        r'(https?|http).*@',                   # @ in URL
        r'\.(tk|ml|ga|cf|gq|top)/',            # Free domains often used for malicious activities
        r'(tiny|bit|goo|is|t)\..*/',           # URL shorteners
        r'(https?|http).*\.php\?',             # PHP with parameters
        r'\.(ru|cn|su|pw|cc|ws)/',             # Domains with high malicious usage rates
        r'([a-zA-Z0-9\-\.]+)\.([a-zA-Z]{2,5})([\/\?].*)?$',  # Domain pattern check
        r'\d{10,}',                            # Very long number
        r'(https?|http).*\.(exe|zip|rar|7z|msi|js|pdf)',  # Executable file extensions
        r'(password|login|signin|credential|verify|account|secure).*\.(com|net|org|io)',  # Security-related with TLD
        r'myaccount.*login',                   # Account related
        r'(bank|paypal|ebay|amazon).*\.([a-zA-Z0-9\-]+)\.([a-zA-Z]{2,5})'  # Popular targets with subdomain
    ]
    
    # Known malicious/phishing domain fragments
    known_bad_domains = [
        "update-account", "login-verify", "secure-signin", "customer-verify", "account-update",
        "security-alert", "verify-account", "signin-secure", "confirm-identity", "password-reset",
        "verification", "authenticate", "authorize", "validation", "phishing", "malware", "trojan",
        "spyware", "account-suspended", "account-limited", "account-locked", "account-disabled",
        "unusual-activity", "suspicious-activity", "suspicious-login", "security-breach", "hacked"
    ]
    
    # Check for suspicious patterns in URL
    pattern_matches = 0
    for pattern in suspicious_patterns:
        if re.search(pattern, url, re.IGNORECASE):
            pattern_matches += 1
    
    # Calculate base suspicion score from patterns (0.0 to 1.0)
    pattern_score = min(pattern_matches * 0.1, 0.6)
    
    # Check for presence of bad domain fragments
    bad_domain_matches = 0
    for bad_fragment in known_bad_domains:
        if bad_fragment in full_domain.lower() or bad_fragment in url.lower():
            bad_domain_matches += 1
    
    # Calculate bad domain score (0.0 to 1.0)
    bad_domain_score = min(bad_domain_matches * 0.2, 0.8)
    
    # Combined initial suspicion score
    combined_suspicion = max(pattern_score, bad_domain_score)
    
    # If suspicious enough to categorize
    if combined_suspicion > 0.2:
        # Determine which threat category it falls into
        threat_scores = {}
        for threat_type, keywords in threat_keywords.items():
            # Count occurrences of keywords
            count = sum(1 for keyword in keywords if keyword in url.lower())
            # Calculate score based on keyword density
            threat_scores[threat_type] = min(count * 0.1, 0.9)
        
        # Boost specific categories based on patterns
        if any(re.search(r'(https?|http).*\.(exe|zip|dll|msi)', url, re.IGNORECASE) for pattern in suspicious_patterns):
            threat_scores["Malware"] = max(threat_scores.get("Malware", 0), 0.75)
        
        if any(re.search(r'(bank|paypal|signin|verify|account).*', url, re.IGNORECASE) for pattern in suspicious_patterns):
            threat_scores["Phishing"] = max(threat_scores.get("Phishing", 0), 0.65)
            
        if any(re.search(r'(free|offer|prize|winner|discount).*', url, re.IGNORECASE) for pattern in suspicious_patterns):
            threat_scores["Spam"] = max(threat_scores.get("Spam", 0), 0.6)
        
        if any(re.search(r'(hacked|pwned|owned|defaced).*', url, re.IGNORECASE) for pattern in suspicious_patterns):
            threat_scores["Defacement"] = max(threat_scores.get("Defacement", 0), 0.7)
        
        # Find the highest scoring threat category
        max_score = 0
        max_category = "Suspicious"  # Default to Suspicious
        
        for threat_type, score in threat_scores.items():
            if score > max_score:
                max_score = score
                max_category = threat_type
        
        # If we have a significant threat
        if max_score > 0.3:
            category["name"] = max_category
            
            # Confidence is based on the threat score
            category["confidence"] = max(max_score, combined_suspicion)
            
            # Assign risk levels (1-5) based on threat category and confidence
            if max_category == "Malware":
                category["risk_level"] = 5  # Highest risk
            elif max_category == "Phishing":
                category["risk_level"] = 4
            elif max_category == "Defacement":
                category["risk_level"] = 3
            elif max_category == "Suspicious":
                category["risk_level"] = 2
            elif max_category == "Spam":
                category["risk_level"] = 1
            else:
                category["risk_level"] = 1  # Default low risk
            
            # Boost risk level based on confidence
            if category["confidence"] > 0.8 and category["risk_level"] < 5:
                category["risk_level"] += 1
        else:
            # Not enough evidence to classify as a specific threat
            if combined_suspicion > 0.4:
                category["name"] = "Suspicious"
                category["confidence"] = combined_suspicion
                category["risk_level"] = 2
    
    # Update risk levels from database if available
    try:
        import sqlite3
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, risk_level FROM url_categories WHERE name = ?', (category["name"],))
        result = cursor.fetchone()
        if result:
            category["id"] = result[0]
            # Only use db risk level if higher than our calculated one
            if result[1] > category["risk_level"]:
                category["risk_level"] = result[1]
        conn.close()
    except Exception as e:
        print(f"Error retrieving category risk level: {e}")
    
    # Store categorization results
    additional_features['category'] = category
    
    return category
