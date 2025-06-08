from openai import OpenAI
from app.core.config import settings
from app.utils.logger import get_logger
from typing import Any, Dict, List, Optional
import json

logger = get_logger(__name__)

# Initialize the OpenAI client for LM Studio
client = OpenAI(
    base_url=settings.LMSTUDIO_API_URL,
    api_key=settings.LMSTUDIO_API_KEY or "lm-studio"
)

class SecurityAnalyzer:
    def __init__(self, model_name: str):
        self.model_name = model_name

    async def analyze_vulnerabilities(self, system_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze system information for potential vulnerabilities.
        
        Args:
            system_info (Dict[str, Any]): System information including OS, services, ports, etc.
            
        Returns:
            Dict[str, Any]: Analysis results with identified vulnerabilities
        """
        try:
            messages = [
                {"role": "system", "content": "You are a cybersecurity expert analyzing system vulnerabilities."},
                {"role": "user", "content": f"Analyze this system information for security vulnerabilities: {json.dumps(system_info)}"}
            ]
            
            response = client.chat.completions.create(
                model=self.model_name,
                messages=messages,
                response_format={"type": "json_object"}
            )
            
            return json.loads(response.choices[0].message.content)
        except Exception as e:
            logger.error(f"Error in vulnerability analysis: {e}")
            return {"error": str(e)}

    async def generate_security_report(self, analysis_results: Dict[str, Any]) -> str:
        """
        Generate a comprehensive security report from analysis results.
        
        Args:
            analysis_results (Dict[str, Any]): Results from vulnerability analysis
            
        Returns:
            str: Formatted security report
        """
        try:
            messages = [
                {"role": "system", "content": "You are a cybersecurity expert generating detailed security reports."},
                {"role": "user", "content": f"Generate a detailed security report based on these findings: {json.dumps(analysis_results)}"}
            ]
            
            response = client.chat.completions.create(
                model=self.model_name,
                messages=messages
            )
            
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"Error generating security report: {e}")
            return f"Error generating report: {str(e)}"

    async def recommend_security_measures(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Recommend security measures for identified vulnerabilities.
        
        Args:
            vulnerabilities (List[Dict[str, Any]]): List of identified vulnerabilities
            
        Returns:
            List[Dict[str, Any]]: Recommended security measures
        """
        try:
            messages = [
                {"role": "system", "content": "You are a cybersecurity expert providing security recommendations."},
                {"role": "user", "content": f"Recommend security measures for these vulnerabilities: {json.dumps(vulnerabilities)}"}
            ]
            
            response = client.chat.completions.create(
                model=self.model_name,
                messages=messages,
                response_format={"type": "json_object"}
            )
            
            return json.loads(response.choices[0].message.content)
        except Exception as e:
            logger.error(f"Error generating security recommendations: {e}")
            return [{"error": str(e)}]