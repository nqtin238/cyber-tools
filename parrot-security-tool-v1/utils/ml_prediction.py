"""Machine Learning-based vulnerability prediction module"""
import os
import json
import logging
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import sqlite3
import re
import requests
from datetime import datetime

class MLVulnerabilityPredictor:
    """
    Machine learning-based vulnerability prediction.
    Uses historical vulnerability data to predict vulnerabilities
    in new systems and services.
    """
    
    def __init__(self, db_connection=None, db_file=None, model_dir='ml_models'):
        """Initialize with database connection for training data"""
        if db_connection:
            self.conn = db_connection
        elif db_file and os.path.exists(db_file):
            self.conn = sqlite3.connect(db_file)
        else:
            self.conn = None
            
        # Create model directory if it doesn't exist
        self.model_dir = model_dir
        os.makedirs(self.model_dir, exist_ok=True)
        
        # Model files
        self.service_model_file = os.path.join(self.model_dir, 'service_vulnerability_model.joblib')
        self.cve_model_file = os.path.join(self.model_dir, 'cve_severity_model.joblib')
        
        # Training data cache
        self.service_data = None
        self.cve_data = None
        
        # Models
        self.service_model = None
        self.cve_model = None
        
        # Load models if they exist
        self._load_models()
    
    def train_models(self, force=False):
        """Train machine learning models on historical vulnerability data"""
        if not self.conn:
            logging.error("No database connection available for training")
            return False
        
        # Train service vulnerability model
        if force or not os.path.exists(self.service_model_file):
            success = self._train_service_vulnerability_model()
            if not success:
                logging.error("Failed to train service vulnerability model")
        
        # Train CVE severity model
        if force or not os.path.exists(self.cve_model_file):
            success = self._train_cve_severity_model()
            if not success:
                logging.error("Failed to train CVE severity model")
        
        return True
    
    def predict_service_vulnerabilities(self, services):
        """
        Predict vulnerabilities for a list of services
        
        Args:
            services: List of dicts with service info:
                      [{'name': 'http', 'version': '2.4.29', 'port': 80}, ...]
                      
        Returns:
            List of dicts with vulnerability predictions
        """
        if not self.service_model:
            if os.path.exists(self.service_model_file):
                self._load_models()
            else:
                self.train_models()
                
        if not self.service_model:
            logging.error("No service vulnerability model available")
            return []
        
        # Prepare input data
        X = []
        for service in services:
            name = service.get('name', '').lower()
            version = service.get('version', '')
            port = service.get('port', 0)
            
            # Feature engineering
            service_str = f"{name} {version}"
            is_web = 1 if name in ['http', 'https', 'www'] else 0
            is_db = 1 if name in ['mysql', 'postgres', 'mongodb', 'redis', 'oracle'] else 0
            is_admin = 1 if name in ['ssh', 'rdp', 'telnet', 'ftp'] else 0
            is_common_port = 1 if port in [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 5432, 8080] else 0
            has_version = 1 if version else 0
            
            X.append({
                'service_str': service_str,
                'port': port,
                'is_web': is_web,
                'is_db': is_db,
                'is_admin': is_admin,
                'is_common_port': is_common_port,
                'has_version': has_version
            })
        
        if not X:
            return []
        
        # Make predictions
        df = pd.DataFrame(X)
        predictions = self.service_model.predict_proba(df)
        
        # Process predictions
        results = []
        for i, service in enumerate(services):
            if i < len(predictions):
                vuln_probability = predictions[i][1]  # Probability of class 1 (vulnerable)
                if vuln_probability > 0.3:  # Only return predictions with reasonable confidence
                    results.append({
                        'service': service,
                        'probability': float(vuln_probability),
                        'prediction': 'vulnerable' if vuln_probability > 0.5 else 'likely_safe',
                        'potential_cves': self._lookup_potential_cves(service)
                    })
        
        return results
    
    def predict_cve_severity(self, cve_ids):
        """
        Predict severity for CVE IDs that don't have official scores
        
        Args:
            cve_ids: List of CVE IDs
                      
        Returns:
            Dict mapping CVE IDs to predicted severity scores
        """
        if not self.cve_model:
            if os.path.exists(self.cve_model_file):
                self._load_models()
            else:
                self.train_models()
                
        if not self.cve_model:
            logging.error("No CVE severity model available")
            return {}
        
        # First, try to get official scores from NVD
        cve_data = self._fetch_cve_data(cve_ids)
        
        # For any CVEs without official scores, predict them
        missing_cves = [cve for cve in cve_ids if cve not in cve_data or 'score' not in cve_data[cve]]
        if missing_cves:
            # Prepare input data
            X = pd.DataFrame({
                'cve_id': missing_cves,
                'year': [int(cve.split('-')[1]) if '-' in cve else 0 for cve in missing_cves]
            })
            
            # Make predictions
            predictions = self.cve_model.predict(X)
            
            # Add predictions to results
            for i, cve in enumerate(missing_cves):
                if i < len(predictions):
                    if cve not in cve_data:
                        cve_data[cve] = {}
                    cve_data[cve]['score'] = float(predictions[i])
                    cve_data[cve]['is_predicted'] = True
        
        return cve_data
    
    def assess_target_risk(self, target_data):
        """
        Assess the overall risk level of a target based on services and configurations
        
        Args:
            target_data: Dict with target information including services, open ports, etc.
                      
        Returns:
            Risk assessment dict with score and recommendations
        """
        if not self.service_model:
            if os.path.exists(self.service_model_file):
                self._load_models()
            else:
                self.train_models()
        
        # Extract services from target data
        services = []
        if 'ports' in target_data:
            for port_info in target_data['ports']:
                services.append({
                    'name': port_info.get('service', '').lower(),
                    'version': port_info.get('version', ''),
                    'port': port_info.get('port', 0)
                })
        
        # Predict vulnerabilities
        vulnerability_predictions = self.predict_service_vulnerabilities(services)
        
        # Calculate risk score (0-100)
        risk_score = 0
        high_risk_services = []
        
        for pred in vulnerability_predictions:
            service = pred['service']
            probability = pred['probability']
            
            # Weight by service type
            service_weight = 1.0
            if service['name'] in ['http', 'https']:
                service_weight = 1.5  # Web services often have higher impact
            elif service['name'] in ['ssh', 'rdp', 'telnet']:
                service_weight = 1.3  # Admin services are sensitive
            
            # Add to risk score
            service_risk = probability * service_weight * 100
            risk_score += service_risk
            
            if service_risk > 50:
                high_risk_services.append({
                    'name': service['name'],
                    'port': service['port'],
                    'risk_score': service_risk
                })
        
        # Normalize risk score to 0-100 range
        if len(vulnerability_predictions) > 0:
            risk_score = min(100, risk_score / len(vulnerability_predictions))
        
        # Generate recommendations
        recommendations = []
        if high_risk_services:
            recommendations.append(f"Focus on securing these high-risk services: {', '.join([s['name'] for s in high_risk_services])}")
        
        if risk_score > 75:
            recommendations.append("Consider implementing additional security layers such as a web application firewall.")
        
        if 'os' in target_data and target_data.get('os'):
            os_name = target_data['os'].lower()
            if 'windows' in os_name:
                recommendations.append("Ensure Windows systems are fully patched and running current security updates.")
            elif 'linux' in os_name or 'unix' in os_name:
                recommendations.append("Consider implementing SELinux or AppArmor for additional protection.")
        
        # Final assessment
        risk_level = 'Low'
        if risk_score > 75:
            risk_level = 'Critical'
        elif risk_score > 50:
            risk_level = 'High'
        elif risk_score > 25:
            risk_level = 'Medium'
        
        return {
            'target': target_data.get('ip', 'Unknown'),
            'risk_score': risk_score,
            'risk_level': risk_level,
            'potential_vulnerabilities': vulnerability_predictions,
            'high_risk_services': high_risk_services,
            'recommendations': recommendations
        }
    
    def _load_models(self):
        """Load trained machine learning models"""
        try:
            if os.path.exists(self.service_model_file):
                self.service_model = joblib.load(self.service_model_file)
                logging.info("Loaded service vulnerability model")
            
            if os.path.exists(self.cve_model_file):
                self.cve_model = joblib.load(self.cve_model_file)
                logging.info("Loaded CVE severity model")
                
            return True
        except Exception as e:
            logging.error(f"Error loading models: {str(e)}")
            return False
    
    def _train_service_vulnerability_model(self):
        """Train the service vulnerability prediction model"""
        try:
            # Load training data from database
            self._load_service_training_data()
            
            if self.service_data is None or len(self.service_data) < 10:
                logging.warning("Not enough service vulnerability data for training")
                return False
            
            # Prepare training data
            X = self.service_data.drop('is_vulnerable', axis=1)
            y = self.service_data['is_vulnerable']
            
            # Create model pipeline
            self.service_model = Pipeline([
                ('scaler', StandardScaler()),
                ('classifier', RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42))
            ])
            
            # Train model
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
            self.service_model.fit(X_train, y_train)
            
            # Evaluate model
            accuracy = self.service_model.score(X_test, y_test)
            logging.info(f"Service vulnerability model trained with accuracy: {accuracy:.4f}")
            
            # Save model
            joblib.dump(self.service_model, self.service_model_file)
            
            return True
        except Exception as e:
            logging.error(f"Error training service vulnerability model: {str(e)}")
            return False
    
    def _train_cve_severity_model(self):
        """Train the CVE severity prediction model"""
        try:
            # Load training data from database
            self._load_cve_training_data()
            
            if self.cve_data is None or len(self.cve_data) < 10:
                logging.warning("Not enough CVE data for training")
                return False
            
            # Prepare training data
            X = self.cve_data.drop('score', axis=1)
            y = self.cve_data['score']
            
            # Create model pipeline
            self.cve_model = Pipeline([
                ('scaler', StandardScaler()),
                ('regressor', RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42))
            ])
            
            # Train model
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
            self.cve_model.fit(X_train, y_train)
            
            # Evaluate model
            r2 = self.cve_model.score(X_test, y_test)
            logging.info(f"CVE severity model trained with R² score: {r2:.4f}")
            
            # Save model
            joblib.dump(self.cve_model, self.cve_model_file)
            
            return True
        except Exception as e:
            logging.error(f"Error training CVE severity model: {str(e)}")
            return False
    
    def _load_service_training_data(self):
        """Load service vulnerability training data from database"""
        if not self.conn:
            return None
        
        try:
            # Query the database for service vulnerability data
            query = """
                SELECT 
                    p.port, 
                    p.service, 
                    p.version,
                    CASE WHEN EXISTS (
                        SELECT 1 FROM vulnerabilities v 
                        WHERE v.target_id = p.target_id AND v.port = p.port
                    ) THEN 1 ELSE 0 END as is_vulnerable
                FROM 
                    ports p
            """
            df = pd.read_sql_query(query, self.conn)
            
            if len(df) == 0:
                return None
            
            # Feature engineering
            df['service'] = df['service'].fillna('').apply(lambda x: str(x).lower())
            df['version'] = df['version'].fillna('')
            
            # Create features
            df['service_str'] = df['service'] + ' ' + df['version']
            df['is_web'] = df['service'].apply(lambda x: 1 if x in ['http', 'https', 'www'] else 0)
            df['is_db'] = df['service'].apply(lambda x: 1 if x in ['mysql', 'postgres', 'mongodb', 'redis', 'oracle'] else 0)
            df['is_admin'] = df['service'].apply(lambda x: 1 if x in ['ssh', 'rdp', 'telnet', 'ftp'] else 0)
            df['is_common_port'] = df['port'].apply(lambda x: 1 if x in [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 5432, 8080] else 0)
            df['has_version'] = df['version'].apply(lambda x: 1 if x else 0)
            
            # Select features for model
            self.service_data = df[['port', 'is_web', 'is_db', 'is_admin', 'is_common_port', 'has_version', 'is_vulnerable']]
            
            return self.service_data
        except Exception as e:
            logging.error(f"Error loading service training data: {str(e)}")
            return None
    
    def _load_cve_training_data(self):
        """Load CVE severity training data from database"""
        if not self.conn:
            return None
        
        try:
            # Query the database for CVE data
            query = """
                SELECT 
                    cve,
                    score
                FROM 
                    vulnerabilities
                WHERE 
                    cve IS NOT NULL
                    AND score IS NOT NULL
            """
            df = pd.read_sql_query(query, self.conn)
            
            if len(df) == 0:
                return None
            
            # Extract features from CVE IDs
            df['year'] = df['cve'].str.extract(r'CVE-(\d{4})-', expand=False).astype(float)
            
            # Select features for model
            self.cve_data = df[['cve', 'year', 'score']]
            
            return self.cve_data
        except Exception as e:
            logging.error(f"Error loading CVE training data: {str(e)}")
            return None
    
    def _lookup_potential_cves(self, service):
        """Look up potential CVEs for a service"""
        name = service.get('name', '').lower()
        version = service.get('version', '')
        
        # Skip if no name or version
        if not name or not version:
            return []
        
        # Query a vulnerability database
        try:
            # In a real implementation, this would use an API to query NVD or another vulnerability database
            # For this example, we'll simulate it with a few mock results based on the service name and version
            
            # Generate mock CVEs
            current_year = datetime.now().year
            cve_year = current_year if random.random() < 0.7 else current_year - random.randint(1, 3)
            
            cves = []
            for i in range(min(3, random.randint(1, 5))):
                cve_id = f"CVE-{cve_year}-{random.randint(1000, 9999)}"
                cves.append({
                    'id': cve_id,
                    'summary': f"Vulnerability in {name} {version} that allows attackers to {random.choice(['bypass authentication', 'execute code', 'cause denial of service', 'read sensitive information'])}.",
                    'published': f"{cve_year}-{random.randint(1, 12):02d}-{random.randint(1, 28):02d}"
                })
            
            return cves
        except Exception as e:
            logging.error(f"Error looking up potential CVEs: {str(e)}")
            return []
    
    def _fetch_cve_data(self, cve_ids):
        """Fetch CVE data from NVD"""
        result = {}
        
        try:
            # In a real implementation, this would use NVD API
            # For this example, we'll just return mock data
            for cve_id in cve_ids:
                # Extract year from CVE ID
                match = re.search(r'CVE-(\d{4})-', cve_id)
                year = int(match.group(1)) if match else 2020
                
                # Generate mock data
                result[cve_id] = {
                    'id': cve_id,
                    'summary': f"This is a mock description for {cve_id}",
                    'published': f"{year}-{random.randint(1, 12):02d}-{random.randint(1, 28):02d}",
                    'score': random.uniform(4.0, 9.5) if random.random() < 0.8 else None,
                    'severity': random.choice(['HIGH', 'MEDIUM', 'CRITICAL'])
                }
        except Exception as e:
            logging.error(f"Error fetching CVE data: {str(e)}")
        
        return result

    def _extract_features(self, service_data):
        """Extract rich feature set from service data"""
        features = {}
        
        # Basic service info
        service_name = service_data.get('name', '').lower()
        version = service_data.get('version', '')
        port = service_data.get('port', 0)
        
        # Standardize version format
        version_pattern = re.search(r'(\d+)\.(\d+)(?:\.(\d+))?', version)
        if version_pattern:
            major = int(version_pattern.group(1))
            minor = int(version_pattern.group(2))
            patch = int(version_pattern.group(3)) if version_pattern.group(3) else 0
            features['version_major'] = major
            features['version_minor'] = minor
            features['version_patch'] = patch
            features['version_age'] = self._calculate_version_age(service_name, major, minor, patch)
        else:
            features['version_major'] = 0
            features['version_minor'] = 0
            features['version_patch'] = 0
            features['version_age'] = 0
        
        # Service type features
        features['is_web'] = 1 if service_name in ['http', 'https', 'www', 'nginx', 'apache', 'iis'] else 0
        features['is_db'] = 1 if service_name in ['mysql', 'mariadb', 'postgres', 'mssql', 'oracle', 'mongodb'] else 0
        features['is_mail'] = 1 if service_name in ['smtp', 'pop3', 'imap', 'exchange'] else 0
        features['is_admin'] = 1 if service_name in ['ssh', 'rdp', 'telnet', 'vnc', 'winrm'] else 0
        features['is_file'] = 1 if service_name in ['ftp', 'smb', 'nfs', 'samba'] else 0
        
        # Port risk features
        features['is_common_port'] = 1 if port in [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 5432, 8080] else 0
        features['is_high_port'] = 1 if port > 1024 else 0
        features['is_very_high_port'] = 1 if port > 10000 else 0
        
        # Service risk score based on historical vulnerabilities
        features['historical_risk_score'] = self._get_service_historical_risk(service_name)
        
        # Software version risk indicators
        features['is_eol_version'] = self._is_end_of_life_version(service_name, version)
        features['has_lts_marker'] = 1 if 'lts' in version.lower() else 0
        features['has_beta_marker'] = 1 if any(m in version.lower() for m in ['alpha', 'beta', 'rc', 'dev']) else 0
        
        return features

    def _initialize_models(self):
        """Initialize multiple specialized prediction models"""
        self.models = {
            'service_vulnerability': None,  # General service vulnerability model
            'web_vulnerability': None,      # Web-specific vulnerabilities
            'rce_vulnerability': None,      # Remote code execution vulnerabilities
            'auth_vulnerability': None,     # Authentication vulnerabilities
            'dos_vulnerability': None       # Denial of service vulnerabilities
        }
        
        # Load existing models
        for model_name in self.models.keys():
            model_file = os.path.join(self.model_dir, f'{model_name}_model.joblib')
            if os.path.exists(model_file):
                try:
                    self.models[model_name] = joblib.load(model_file)
                    logging.info(f"Loaded {model_name} model")
                except Exception as e:
                    logging.error(f"Error loading {model_name} model: {str(e)}")

    def predict_vulnerabilities(self, service):
        """Make predictions using an ensemble of models"""
        # Extract features
        features = self._extract_features(service)
        
        # Collect predictions from all relevant models
        predictions = {}
        confidence_scores = {}
        
        # General service vulnerability prediction
        if self.models['service_vulnerability']:
            pred = self.models['service_vulnerability'].predict_proba([features])[0]
            predictions['general'] = bool(pred[1] > 0.5)
            confidence_scores['general'] = float(pred[1])
        
        # Specialized predictions based on service type
        if features['is_web'] == 1 and self.models['web_vulnerability']:
            pred = self.models['web_vulnerability'].predict_proba([features])[0]
            predictions['web'] = bool(pred[1] > 0.5)
            confidence_scores['web'] = float(pred[1])
        
        # Authentication vulnerability prediction for admin services
        if features['is_admin'] == 1 and self.models['auth_vulnerability']:
            pred = self.models['auth_vulnerability'].predict_proba([features])[0]
            predictions['auth'] = bool(pred[1] > 0.5)
            confidence_scores['auth'] = float(pred[1])
        
        # Weighted ensemble score
        ensemble_score = self._calculate_ensemble_score(confidence_scores, service_type=service['name'])
        
        # Return comprehensive prediction result
        return {
            'service': service,
            'predictions': predictions,
            'confidence_scores': confidence_scores,
            'ensemble_score': ensemble_score,
            'is_vulnerable': ensemble_score > 0.6,
            'potential_cves': self._lookup_potential_cves(service) if ensemble_score > 0.4 else []
        }

    def update_model_with_feedback(self, prediction, actual_result):
        """Update models with feedback on predictions (active learning)"""
        # Extract features from the original service
        service = prediction['service']
        features = self._extract_features(service)
        
        # Convert to numpy arrays for model update
        X = np.array([list(features.values())])
        y = np.array([1 if actual_result else 0])
        
        # Update the appropriate models
        service_type = service.get('name', '').lower()
        
        # Update general model
        if self.models['service_vulnerability']:
            self.models['service_vulnerability'].partial_fit(X, y)
            
        # Update specialized models
        if service_type in ['http', 'https', 'www'] and self.models['web_vulnerability']:
            self.models['web_vulnerability'].partial_fit(X, y)
        elif service_type in ['ssh', 'rdp', 'telnet'] and self.models['auth_vulnerability']:
            self.models['auth_vulnerability'].partial_fit(X, y)
        
        # Save updated models
        self._save_models()
        
        logging.info(f"Updated prediction models with feedback for {service_type} service")
        return True

    def explain_prediction(self, prediction):
        """Generate human-readable explanation for a prediction"""
        service = prediction['service']
        service_name = service.get('name', '').lower()
        ensemble_score = prediction['ensemble_score']
        
        # Use SHAP values to get feature importance
        features = self._extract_features(service)
        feature_importance = self._calculate_feature_importance(features, service_name)
        
        # Generate explanation based on top contributing factors
        explanation = {
            'summary': f"The {service_name} service on port {service.get('port')} {'is likely vulnerable' if ensemble_score > 0.6 else 'may be vulnerable' if ensemble_score > 0.4 else 'appears secure'}.",
            'confidence': f"{ensemble_score:.1%}",
            'key_factors': [],
            'recommendations': []
        }
        
        # Add top contributing factors
        for factor, importance in sorted(feature_importance.items(), key=lambda x: x[1], reverse=True)[:3]:
            if importance > 0.1:  # Only include significant factors
                if factor == 'version_age' and features['version_age'] > 0:
                    explanation['key_factors'].append(f"The software version is {features['version_age']} years old")
                elif factor == 'is_eol_version' and features['is_eol_version'] == 1:
                    explanation['key_factors'].append(f"The software version has reached end-of-life")
                elif factor == 'has_beta_marker' and features['has_beta_marker'] == 1:
                    explanation['key_factors'].append(f"The software is using a pre-release/beta version")
        
        # Add recommendations based on prediction
        if ensemble_score > 0.4:
            if features['version_age'] > 2:
                explanation['recommendations'].append(f"Update {service_name} to the latest stable version")
            if features['is_eol_version'] == 1:
                explanation['recommendations'].append(f"Replace this end-of-life software with a supported alternative")
        
        return explanation

    def _enrich_with_external_data(self):
        """Enrich model with data from external vulnerability databases"""
        # NVD Data
        nvd_data = self._fetch_nvd_data()
        if nvd_data:
            self._integrate_nvd_data(nvd_data)
        
        # ExploitDB data
        exploitdb_data = self._fetch_exploitdb_data()
        if exploitdb_data:
            self._integrate_exploitdb_data(exploitdb_data)
        
        # Vendor security advisories
        vendor_data = self._fetch_vendor_advisories()
        if vendor_data:
            self._integrate_vendor_data(vendor_data)
        
        logging.info("Enriched ML models with external vulnerability data")

    def assess_contextual_risk(self, target_data, network_data=None):
        """Assess risk with network context awareness"""
        # Basic risk assessment
        risk_assessment = self.assess_target_risk(target_data)
        
        # If we have network data, enhance with contextual factors
        if network_data:
            # Check for internet exposure
            is_exposed = self._is_internet_exposed(target_data['ip'], network_data)
            if is_exposed:
                risk_assessment['risk_score'] *= 1.5  # Increase risk for internet-exposed services
                risk_assessment['contextual_factors'] = ["Internet-exposed service increases risk"]
            
            # Check if system is in DMZ
            in_dmz = self._is_in_dmz(target_data['ip'], network_data)
            if in_dmz:
                risk_assessment['risk_score'] *= 1.3  # Increase risk for DMZ systems
                if 'contextual_factors' not in risk_assessment:
                    risk_assessment['contextual_factors'] = []
                risk_assessment['contextual_factors'].append("System is in DMZ")
            
            # Check if system has sensitive data
            has_sensitive_data = self._has_sensitive_data(target_data['ip'], network_data)
            if has_sensitive_data:
                risk_assessment['risk_score'] *= 1.4  # Increase risk for systems with sensitive data
                if 'contextual_factors' not in risk_assessment:
                    risk_assessment['contextual_factors'] = []
                risk_assessment['contextual_factors'].append("System contains sensitive data")
            
            # Normalize score to 0-100
            risk_assessment['risk_score'] = min(100, risk_assessment['risk_score'])
        
        return risk_assessment

# Example usage
if __name__ == "__main__":
    import random
    
    # Create predictor
    predictor = MLVulnerabilityPredictor()
    
    # Example services
    services = [
        {'name': 'http', 'version': 'Apache 2.4.29', 'port': 80},
        {'name': 'ssh', 'version': 'OpenSSH 7.6p1', 'port': 22},
        {'name': 'mysql', 'version': '5.7.38', 'port': 3306}
    ]
    
    # Predict vulnerabilities
    predictions = predictor.predict_service_vulnerabilities(services)
    
    # Print predictions
    for pred in predictions:
        print(f"Service: {pred['service']['name']} {pred['service']['version']}")
        print(f"Vulnerability probability: {pred['probability']:.2f}")
        print(f"Prediction: {pred['prediction']}")
        if pred['potential_cves']:
            print("Potential CVEs:")
            for cve in pred['potential_cves']:
                print(f"  - {cve['id']}: {cve['summary']}")
        print()
    
    # Example target assessment
    target = {
        'ip': '192.168.1.1',
        'os': 'Ubuntu Linux 20.04',
        'ports': [
            {'port': 22, 'service': 'ssh', 'version': 'OpenSSH 8.2p1'},
            {'port': 80, 'service': 'http', 'version': 'nginx 1.18.0'},
            {'port': 443, 'service': 'https', 'version': 'nginx 1.18.0'},
            {'port': 3306, 'service': 'mysql', 'version': '8.0.25'}
        ]
    }
    
    assessment = predictor.assess_target_risk(target)
    
    print(f"Target: {assessment['target']}")
    print(f"Risk Level: {assessment['risk_level']} ({assessment['risk_score']:.1f}/100)")
    if assessment['high_risk_services']:
        print("High-risk services:")
        for service in assessment['high_risk_services']:
            print(f"  - {service['name']} on port {service['port']} (score: {service['risk_score']:.1f})")
    print("Recommendations:")
    for rec in assessment['recommendations']:
        print(f"  - {rec}")