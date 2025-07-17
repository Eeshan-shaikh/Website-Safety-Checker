import models

def test_url(url):
    print(f"Testing URL: {url}")
    
    # Load the model first
    models.URLSafetyModel.load_model()
    
    # Extract features
    features = models.extract_features(url)
    
    # Get prediction
    prediction = models.URLSafetyModel.predict(features)
    
    print(f"Prediction: {'SAFE' if prediction else 'UNSAFE'}")
    
    # Check what triggered the unsafe classification
    if not prediction:
        if models.additional_features.get('brand_impersonation', {}).get('detected', False):
            print("Triggered by: Brand Impersonation")
            print(f"Details: {models.additional_features.get('brand_impersonation')}")
            
        if models.additional_features.get('giveaway_scam', {}).get('multiple_indicators', False):
            print("Triggered by: Giveaway Scam")
            print(f"Details: {models.additional_features.get('giveaway_scam')}")
            
        if models.additional_features.get('tech_support_scam', {}).get('detected', False):
            print("Triggered by: Tech Support Scam")
            print(f"Details: {models.additional_features.get('tech_support_scam')}")
            
        if models.additional_features.get('financial_scam', {}).get('detected', False):
            print("Triggered by: Financial Scam")
            print(f"Details: {models.additional_features.get('financial_scam')}")
            
        if models.additional_features.get('domain_confusion', {}).get('detected', False):
            print("Triggered by: Domain Confusion")
            print(f"Details: {models.additional_features.get('domain_confusion')}")
    
    print("\nAdditional feature details:")
    for key, value in models.additional_features.items():
        if isinstance(value, dict) and key != 'brand_impersonation' and key != 'giveaway_scam' and key != 'tech_support_scam' and key != 'financial_scam' and key != 'domain_confusion':
            print(f"  {key}: {value}")
        elif not isinstance(value, dict):
            print(f"  {key}: {value}")

if __name__ == "__main__":
    test_url("http://google.com")
    print("\n" + "-"*50 + "\n")
    test_url("http://evil-site-google.com")