from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_anonymizer import AnonymizerEngine
import time

# Set up the main engines
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

# Customization 1: Find AWS keys
# Customization 2: Boost score if words like key or secret are near it
custom_pattern = Pattern(name="dev_key", regex=r"AKIA[0-9A-Z]{16}", score=0.4)
key_finder = PatternRecognizer(
    supported_entity="DEV_API_KEY",
    patterns=[custom_pattern],
    context=["key", "api", "auth", "secret"]
)
analyzer.registry.add_recognizer(key_finder)

def scan_for_injection(text):
    bad_words = ["bypass", "ignore", "jailbreak", "admin mode", "system prompt"]
    risk = 0.0
    for word in bad_words:
        if word in text.lower():
            risk += 0.5
    return risk

def run_security_pipeline(user_text):
    start_time = time.time()

    # Step 1: Check for prompt injections
    injection_risk = scan_for_injection(user_text)
    
    # We block if risk is 0.8 or higher
    if injection_risk >= 0.8:
        time_taken = round((time.time() - start_time) * 1000, 2)
        return "BLOCK", "Warning: Injection detected.", time_taken

    # Step 2: Check for private data
    found_data = analyzer.analyze(
        text=user_text,
        entities=["PERSON", "EMAIL_ADDRESS", "DEV_API_KEY"],
        language="en"
    )

    # Customization 3: Only hide things if we are very sure (confidence 0.6)
    good_results = [item for item in found_data if item.score >= 0.6]

    # Step 3: Make the decision
    if len(good_results) > 0:
        safe_text = anonymizer.anonymize(text=user_text, analyzer_results=good_results).text
        time_taken = round((time.time() - start_time) * 1000, 2)
        return "MASK", safe_text, time_taken

    time_taken = round((time.time() - start_time) * 1000, 2)
    return "ALLOW", user_text, time_taken
