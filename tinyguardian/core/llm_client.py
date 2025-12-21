"""
LLM Client
Handles communication with local LLM providers (Ollama, LM Studio, llama.cpp).
"""

from typing import Optional, Dict, List
from enum import Enum
import requests
from loguru import logger
import json


class LLMProvider(str, Enum):
    """Supported LLM providers."""
    OLLAMA = "ollama"
    LM_STUDIO = "lm_studio"
    LLAMA_CPP = "llama_cpp"


class LLMClient:
    """
    Client for interacting with local LLM providers.
    """
    
    def __init__(self,
                 provider: str = "ollama",
                 model: str = "phi3:mini",
                 base_url: str = "http://localhost:11434",
                 temperature: float = 0.3,
                 max_tokens: int = 500):
        """
        Initialize LLM client.
        
        Args:
            provider: LLM provider (ollama, lm_studio, llama_cpp)
            model: Model name
            base_url: Base URL for API
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate
        """
        self.provider = LLMProvider(provider.lower())
        self.model = model
        self.base_url = base_url.rstrip('/')
        self.temperature = temperature
        self.max_tokens = max_tokens
        
        logger.info(f"Initialized LLM client: {self.provider.value} with model {self.model}")
    
    def analyze_log(self, log_message: str, device_id: str) -> Dict:
        """
        Analyze a log message and return threat assessment.
        
        Args:
            log_message: Log message to analyze
            device_id: Device identifier
            
        Returns:
            Dictionary with analysis results
        """
        prompt = self._build_analysis_prompt(log_message, device_id)
        
        try:
            response = self._generate(prompt)
            return self._parse_response(response)
        except Exception as e:
            logger.error(f"Error analyzing log: {e}")
            return {
                "threat_level": "unknown",
                "severity": 0.0,
                "explanation": f"Error analyzing log: {str(e)}",
                "recommendation": "Review log manually"
            }
    
    def _build_analysis_prompt(self, log_message: str, device_id: str) -> str:
        """Build prompt for log analysis."""
        return f"""You are a cybersecurity expert analyzing IoT device logs. Analyze the following log message and determine if it indicates a security threat.

Device ID: {device_id}
Log Message: {log_message}

Provide your analysis in JSON format with the following fields:
- threat_level: "none", "low", "medium", "high", or "critical"
- severity: float between 0.0 and 1.0
- explanation: brief explanation of what the log indicates
- recommendation: actionable security recommendation

Focus on:
- Unauthorized access attempts
- Unusual network activity
- Authentication failures
- Configuration changes
- Anomalous behavior patterns

JSON Response:"""
    
    def _generate(self, prompt: str) -> str:
        """Generate response from LLM."""
        if self.provider == LLMProvider.OLLAMA:
            return self._generate_ollama(prompt)
        elif self.provider == LLMProvider.LM_STUDIO:
            return self._generate_lm_studio(prompt)
        else:
            raise ValueError(f"Unsupported provider: {self.provider}")
    
    def _generate_ollama(self, prompt: str) -> str:
        """Generate using Ollama API."""
        url = f"{self.base_url}/api/generate"
        
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "num_predict": self.max_tokens
            }
        }
        
        response = requests.post(url, json=payload, timeout=30)
        response.raise_for_status()
        
        result = response.json()
        return result.get("response", "")
    
    def _generate_lm_studio(self, prompt: str) -> str:
        """Generate using LM Studio API (OpenAI-compatible)."""
        url = f"{self.base_url}/v1/chat/completions"
        
        payload = {
            "model": self.model,
            "messages": [
                {"role": "user", "content": prompt}
            ],
            "temperature": self.temperature,
            "max_tokens": self.max_tokens
        }
        
        response = requests.post(url, json=payload, timeout=30)
        response.raise_for_status()
        
        result = response.json()
        return result["choices"][0]["message"]["content"]
    
    def _parse_response(self, response: str) -> Dict:
        """Parse LLM response into structured format."""
        # Try to extract JSON from response
        try:
            # Look for JSON block
            if "```json" in response:
                json_start = response.find("```json") + 7
                json_end = response.find("```", json_start)
                json_str = response[json_start:json_end].strip()
            elif "```" in response:
                json_start = response.find("```") + 3
                json_end = response.find("```", json_start)
                json_str = response[json_start:json_end].strip()
            else:
                # Try to find JSON object
                json_start = response.find("{")
                json_end = response.rfind("}") + 1
                json_str = response[json_start:json_end]
            
            parsed = json.loads(json_str)
            
            # Validate and normalize
            threat_level = parsed.get("threat_level", "unknown").lower()
            severity = float(parsed.get("severity", 0.0))
            explanation = parsed.get("explanation", "No explanation provided")
            recommendation = parsed.get("recommendation", "No recommendation")
            
            return {
                "threat_level": threat_level,
                "severity": max(0.0, min(1.0, severity)),
                "explanation": explanation,
                "recommendation": recommendation
            }
        except Exception as e:
            logger.warning(f"Failed to parse JSON response: {e}")
            # Fallback: extract information from text
            threat_level = "unknown"
            severity = 0.5
            
            if any(word in response.lower() for word in ["critical", "high", "severe"]):
                threat_level = "high"
                severity = 0.8
            elif any(word in response.lower() for word in ["medium", "moderate"]):
                threat_level = "medium"
                severity = 0.5
            elif any(word in response.lower() for word in ["low", "minor"]):
                threat_level = "low"
                severity = 0.3
            elif any(word in response.lower() for word in ["none", "normal", "safe"]):
                threat_level = "none"
                severity = 0.0
            
            return {
                "threat_level": threat_level,
                "severity": severity,
                "explanation": response[:500],  # First 500 chars
                "recommendation": "Review log manually"
            }
    
    def test_connection(self) -> bool:
        """Test connection to LLM provider."""
        try:
            if self.provider == LLMProvider.OLLAMA:
                response = requests.get(f"{self.base_url}/api/tags", timeout=5)
                return response.status_code == 200
            elif self.provider == LLMProvider.LM_STUDIO:
                response = requests.get(f"{self.base_url}/v1/models", timeout=5)
                return response.status_code == 200
            return False
        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            return False

