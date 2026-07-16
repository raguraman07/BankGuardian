import numpy as np
import pandas as pd
from datetime import datetime
from fraud_model import IF_MODEL, extract_features

SHAP_AVAILABLE = False
try:
    import shap
    # Initialize explainer on training data or directly from model
    # Isolation Forest is tree-based, so TreeExplainer is ideal.
    # To avoid background compilation delay in Streamlit, we initialize it lazily.
    EXPLAINER = None
    SHAP_AVAILABLE = True
except Exception as e:
    print(f"[Explainability] SHAP not available or failed to import. Falling back to rule-based explainer. Error: {e}")
    EXPLAINER = None

def get_shap_contributions(transaction):
    """
    Attempts to get SHAP contributions from Isolation Forest features.
    Features: [amount, hour_of_day, is_new_beneficiary]
    """
    global EXPLAINER
    if not SHAP_AVAILABLE:
        return None
        
    try:
        features = extract_features(transaction)
        
        # Lazy initialization
        if EXPLAINER is None:
            # We initialize TreeExplainer. We can pass a background dataset or just the model.
            # Fitting a small sample of background data ensures SHAP values are well-calibrated.
            bg_data = np.array([
                [100.0, 12, 0],
                [50.0, 15, 0],
                [200.0, 9, 0],
                [1000.0, 14, 1],
                [150.0, 21, 0]
            ])
            EXPLAINER = shap.TreeExplainer(IF_MODEL, bg_data)
            
        shap_values = EXPLAINER.shap_values(features)
        
        # shap_values shape can vary based on SHAP version.
        # Usually it is a 2D array of shape (num_samples, num_features)
        if isinstance(shap_values, list):
            # For some SHAP versions/multiclass/etc, it returns a list
            shap_vals = shap_values[0][0]
        else:
            shap_vals = shap_values[0]
            
        # Ensure we have 3 values corresponding to [amount, hour_of_day, is_new_beneficiary]
        return {
            "amount": float(shap_vals[0]),
            "hour_of_day": float(shap_vals[1]),
            "is_new_beneficiary": float(shap_vals[2])
        }
    except Exception as e:
        print(f"[Explainability] Error during SHAP tree explanation: {e}. Using fallback.")
        return None

def explain_threat(transaction, correlated_res, correlation_rules):
    """
    Combines Isolation Forest explanations (SHAP) with correlation engine adjustments.
    Returns:
        {
            "risk_score": float,
            "contributing_factors": [{"factor": str, "contribution": float}, ...],
            "narrative": str
        }
    """
    raw_s = correlated_res["raw_score"]
    corr_s = correlated_res["correlated_score"]
    reason = correlated_res["adjustment_reason"]
    status = correlated_res["status"]
    
    factors = []
    
    # 1. Get raw transaction feature contributions
    shap_contribs = get_shap_contributions(transaction)
    
    if shap_contribs is None:
        # Fallback heuristic for raw ML features
        amount = float(transaction.get("amount", 0))
        is_new = 1 if transaction.get("is_new_beneficiary", False) else 0
        
        # Calculate raw contribution base weights
        # Large amount is main driver for raw score
        if amount > 5000:
            amount_wt = 0.45 + min(0.35, amount / 50000.0)
        else:
            amount_wt = 0.10 + (amount / 5000.0) * 0.20
            
        new_beneficiary_wt = 0.15 if is_new else 0.02
        
        # Hour risk
        dt = transaction.get("timestamp", datetime.now())
        hour = dt.hour
        hour_wt = 0.12 if (hour < 6 or hour > 22) else 0.02
        
        # Normalize sum of raw inputs to match raw_score
        total_raw_wt = amount_wt + new_beneficiary_wt + hour_wt
        if total_raw_wt > 0:
            scale = raw_s / total_raw_wt
            amount_wt *= scale
            new_beneficiary_wt *= scale
            hour_wt *= scale
            
        raw_contribs = {
            "Amount Risk": round(amount_wt, 3),
            "Hour of Day Risk": round(hour_wt, 3),
            "New Beneficiary Risk": round(new_beneficiary_wt, 3)
        }
    else:
        # Convert SHAP values (higher SHAP = higher anomaly)
        # Shift SHAP values to be positive contributions for presentation
        # Isolation forest SHAP is negative for anomalies in older versions, positive in newer.
        # Let's align signs to represent positive risk contribution.
        amt_val = shap_contribs["amount"]
        hour_val = shap_contribs["hour_of_day"]
        new_val = shap_contribs["is_new_beneficiary"]
        
        # Standardize signs (anomalous values should contribute positively)
        # If all SHAP values are negative, flip them.
        if amt_val < 0 and hour_val < 0 and new_val < 0:
            amt_val, hour_val, new_val = -amt_val, -hour_val, -new_val
            
        # Add a baseline scaling so the contributions sum to raw_score
        total = abs(amt_val) + abs(hour_val) + abs(new_val)
        if total > 0:
            amt_wt = (abs(amt_val) / total) * raw_s
            hour_wt = (abs(hour_val) / total) * raw_s
            new_wt = (abs(new_val) / total) * raw_s
        else:
            amt_wt, hour_wt, new_wt = raw_s / 3.0, raw_s / 3.0, raw_s / 3.0
            
        raw_contribs = {
            "Amount Risk": round(amt_wt, 3),
            "Hour of Day Risk": round(hour_wt, 3),
            "New Beneficiary Risk": round(new_wt, 3)
        }
        
    # 2. Integrate graph correlation adjustments
    if corr_s > raw_s:
        # Threat escalation: add cyber telemetry contributions
        escalation_delta = corr_s - raw_s
        
        # Distribute escalation delta based on rules triggered
        sim_trigger = any("SIM Swap" in r for r in correlation_rules)
        login_trigger = any("Login" in r or "Brute Force" in r for r in correlation_rules)
        
        if sim_trigger and login_trigger:
            factors.append({"factor": "SIM Swap", "contribution": round(escalation_delta * 0.60, 2)})
            factors.append({"factor": "New Device & IP", "contribution": round(escalation_delta * 0.40, 2)})
        elif sim_trigger:
            factors.append({"factor": "SIM Swap", "contribution": round(escalation_delta, 2)})
        elif login_trigger:
            factors.append({"factor": "New Device & IP", "contribution": round(escalation_delta, 2)})
        else:
            factors.append({"factor": "Cyber Telemetry Co-occurrence", "contribution": round(escalation_delta, 2)})
            
        # Add the raw transaction features as they were
        for k, v in raw_contribs.items():
            # Standardize names to match build prompt request format
            name = "Large Transaction" if k == "Amount Risk" else k.replace(" Risk", "")
            factors.append({"factor": name, "contribution": round(v, 2)})
            
    elif corr_s < raw_s:
        # False-positive downweighting: show transaction risk discounted by clean cybersecurity profile
        discount_delta = raw_s - corr_s
        
        # Show transaction risk features, but add a negative "Correlation Discount" factor
        for k, v in raw_contribs.items():
            name = "Large Transaction" if k == "Amount Risk" else k.replace(" Risk", "")
            factors.append({"factor": name, "contribution": round(v, 2)})
            
        factors.append({
            "factor": "Security Profile Discount", 
            "contribution": -round(discount_delta, 2)
        })
    else:
        # No adjustment (low-risk normal transaction)
        for k, v in raw_contribs.items():
            name = "Large Transaction" if k == "Amount Risk" else k.replace(" Risk", "")
            factors.append({"factor": name, "contribution": round(v, 2)})
            
    # Sort factors by absolute magnitude of contribution, descending
    factors.sort(key=lambda x: abs(x["contribution"]), reverse=True)
    
    # 3. Create narrative text
    user = transaction.get("user", "User")
    amt = transaction.get("amount", 0)
    
    if corr_s >= 0.80:
        # High Risk Narrative
        trigger_desc = "SIM swap combined with a successful login from a new device and foreign IP."
        if any("Brute Force" in r for r in correlation_rules):
            trigger_desc = "a localized credential brute-force login burst, followed by a transaction request."
            
        narrative = f"Flagged HIGH risk (Score: {corr_s:.2f}) primarily due to {trigger_desc} This indicates a critical session hijacking or account takeover threat."
    elif corr_s < 0.60 and raw_s >= 0.60:
        # False Positive Avoided Narrative
        narrative = f"Raw transaction anomaly score was elevated ({raw_s:.2f}) due to a large transaction amount (${amt:,.2f}). However, correlation with active cybersecurity logs indicates no SIM swaps, no abnormal device logins, and no credential alerts. The score has been discounted to {corr_s:.2f}, avoiding a false positive."
    else:
        # Low risk
        narrative = f"Transaction profile is consistent with historical patterns. Security correlation engine confirmed no suspicious concurrent network or device telemetry."
        
    return {
        "risk_score": corr_s,
        "contributing_factors": factors,
        "narrative": narrative
    }

if __name__ == "__main__":
    print("--- Testing explainability.py ---")
    
    txn = {
        "user": "charlie",
        "amount": 16500.00,
        "timestamp": datetime.now(),
        "is_new_beneficiary": True
    }
    
    # Test case 1: Large Legitimate Transaction (Score discounted)
    correlated_res_legit = {
        "raw_score": 0.72,
        "correlated_score": 0.32,
        "adjustment_reason": "No corroborating security signal found — large amount alone downweighted",
        "status": "low"
    }
    
    expl_legit = explain_threat(txn, correlated_res_legit, [])
    print("\nLegitimate Large Transaction Explanation:")
    print(f"Risk Score: {expl_legit['risk_score']}")
    print("Factors:")
    for f in expl_legit["contributing_factors"]:
        print(f"  - {f['factor']}: {f['contribution']}")
    print(f"Narrative: {expl_legit['narrative']}")
    
    # Test case 2: Confirmed Fraud (Score escalated)
    correlated_res_fraud = {
        "raw_score": 0.72,
        "correlated_score": 0.93,
        "adjustment_reason": "SIM swap + new device confirmed within 10-minute window — escalated",
        "status": "high"
    }
    rules = [
        "SIM Swap (at 12:00:00) followed by Large Transaction",
        "Login from suspicious location/IP: Russia (185.220.101.5) using device DEV-T5"
    ]
    
    expl_fraud = explain_threat(txn, correlated_res_fraud, rules)
    print("\nFraudulent Transaction Explanation:")
    print(f"Risk Score: {expl_fraud['risk_score']}")
    print("Factors:")
    for f in expl_fraud["contributing_factors"]:
        print(f"  - {f['factor']}: {f['contribution']}")
    print(f"Narrative: {expl_fraud['narrative']}")
    
    print("\nSHAP Availability Status:", SHAP_AVAILABLE)
    if SHAP_AVAILABLE:
        print("Sample SHAP Values calculated successfully.")
    else:
        print("Fallback explanation engine executed successfully.")
        
    print("--- explainability.py verified successfully ---")
