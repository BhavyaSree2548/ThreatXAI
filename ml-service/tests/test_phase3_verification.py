from __future__ import annotations

import csv
import json
from pathlib import Path
import httpx

BASE_URL = 'http://127.0.0.1:8000'
ROOT = Path(__file__).resolve().parents[2]
SAMPLE_PATH = ROOT / 'frontend' / 'public' / 'samples' / 'cic-ids2017-real-sample.csv'
SCHEMA_PATH = ROOT / 'ml-service' / 'artifacts' / 'model_feature_schema.json'

schema = json.loads(SCHEMA_PATH.read_text(encoding='utf-8'))
feature_names = [f['model_name'] for f in schema['features']]

def main() -> None:
    print('=== THREATXAI PHASE 3 VERIFICATION SUITE ===')
    with httpx.Client(base_url=BASE_URL, timeout=30.0) as client:
        # 1. Health Endpoint Test
        res = client.get('/health')
        assert res.status_code == 200, f'Health failed: {res.status_code}'
        data = res.json()
        assert data['status'] == 'ok'
        assert data['model_loaded'] is True
        assert data['feature_count'] == 78
        assert data['class_count'] == 15
        print('[PASS] 1. GET /health verified (78 features, 15 classes, model loaded).')

        # 2. Sample Data Load
        with SAMPLE_PATH.open(newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            records = list(reader)
        assert len(records) == 3

        # 3. Test Predictions and Explanations for all classes
        expected_types = ['BENIGN', 'DDoS', 'PortScan']
        for idx, (rec, expected_cls) in enumerate(zip(records, expected_types, strict=True), start=2):
            payload = {'features': {name: float(rec[name]) for name in feature_names}}

            # /predict
            p_res = client.post('/predict', json=payload)
            assert p_res.status_code == 200, f'Predict failed: {p_res.text}'
            p_data = p_res.json()
            assert p_data['prediction'] == expected_cls
            assert 0.0 <= p_data['confidence'] <= 1.0
            assert len(p_data['class_probabilities']) == 15
            assert (p_data['status'] == 'BENIGN' if expected_cls == 'BENIGN' else p_data['status'] == 'MALICIOUS')

            # /explain
            e_res = client.post('/explain', json=payload)
            assert e_res.status_code == 200, f'Explain failed: {e_res.text}'
            e_data = e_res.json()
            assert e_data['prediction'] == expected_cls
            assert e_data['confidence'] == p_data['confidence']
            assert len(e_data['explanation']) == 10
            assert all(item['feature'] in feature_names for item in e_data['explanation'])
            assert 'summary' in e_data and len(e_data['summary']) > 10
            assert 'supporting_features' in e_data
            assert 'opposing_features' in e_data
            assert all(item['shap_value'] > 0 for item in e_data['supporting_features'])
            assert all(item['shap_value'] < 0 for item in e_data['opposing_features'])

            pred_name = p_data['prediction']
            conf_pct = p_data['confidence'] * 100
            top_f = e_data['explanation'][0]['feature'].strip()
            top_shap = e_data['explanation'][0]['shap_value']
            summary_text = e_data['summary']
            print(f'       Summary: {summary_text}')

        # 4. Input Validation Tests
        res_missing = client.post('/predict', json={'features': {feature_names[i]: 1.0 for i in range(77)}})
        assert res_missing.status_code == 422
        print('[PASS] 3a. Missing feature rejected with 422.')

        res_extra = client.post('/predict', json={'features': {**{feature_names[i]: 1.0 for i in range(78)}, 'Unknown_Col': 1.0}})
        assert res_extra.status_code == 422
        print('[PASS] 3b. Unexpected feature rejected with 422.')

        shuffled = list(feature_names)
        shuffled[0], shuffled[1] = shuffled[1], shuffled[0]
        res_order = client.post('/predict', json={'features': {name: 1.0 for name in shuffled}})
        assert res_order.status_code == 422
        print('[PASS] 3c. Incorrect feature order rejected with 422.')

        res_invalid_val = client.post('/explain', json={'features': {**{name: 1.0 for name in feature_names}, feature_names[0]: 'not-a-number'}})
        assert res_invalid_val.status_code == 422
        print('[PASS] 3d. Non-numeric value rejected with 422.')

        print('=== ALL PHASE 3 TESTS PASSED PERFECTLY! ===')


if __name__ == '__main__':
    main()

