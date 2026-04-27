from __future__ import annotations

import os
from typing import Iterable

import requests

try:
    import ollama
except ImportError:  # pragma: no cover - optional runtime dependency
    ollama = None


class AIClient:
    PROVIDERS = {
        "ollama": None,
        "openai": "https://api.openai.com/v1",
        "deepseek": "https://api.deepseek.com/v1",
        "nvidia": "https://integrate.api.nvidia.com/v1",
        "custom": None,
    }

    DEFAULT_MODELS = {
        "ollama": "deepseek-r1:8b",
        "openai": "gpt-3.5-turbo",
        "deepseek": "deepseek-chat",
        "nvidia": "meta/llama3-70b-instruct",
        "custom": "default",
    }

    def __init__(
        self,
        provider: str = "ollama",
        api_key: str | None = None,
        model: str | None = None,
        api_base: str | None = None,
        timeout: int = 10,
        allow_api_base_override: bool = False,
        request_max_tokens: int = 1000,
        json_response_providers: Iterable[str] = ("openai", "deepseek"),
        verbose_http_errors: bool = False,
        test_timeout: int = 15,
    ) -> None:
        self.provider = provider.lower()
        self.api_key = api_key or default_api_key_for_provider(self.provider)
        self.model = model or self.DEFAULT_MODELS.get(self.provider, "default")
        self.timeout = timeout
        self.allow_api_base_override = allow_api_base_override
        self.request_max_tokens = request_max_tokens
        self.json_response_providers = {item.lower() for item in json_response_providers}
        self.verbose_http_errors = verbose_http_errors
        self.test_timeout = test_timeout

        if self.provider == "ollama":
            self.api_base = api_base
        elif api_base and allow_api_base_override:
            self.api_base = api_base
        elif self.provider == "custom":
            self.api_base = api_base or "http://localhost:8080/v1"
        else:
            self.api_base = self.PROVIDERS.get(self.provider, "https://api.openai.com/v1")

    def test_connection(self) -> dict:
        try:
            if self.provider == "ollama":
                return self._test_ollama()
            return self._test_openai_compatible()
        except Exception as exc:  # pragma: no cover - defensive
            return {"success": False, "message": str(exc), "model": self.model}

    def chat(self, prompt: str, system_prompt: str | None = None) -> str:
        if self.provider == "ollama":
            return self._call_ollama(prompt, system_prompt)
        return self._call_openai_compatible(prompt, system_prompt)

    def _ollama_client(self):
        if ollama is None:
            raise RuntimeError("ollama package is not installed")
        return ollama.Client(host=self.api_base)

    def _test_ollama(self) -> dict:
        try:
            client = self._ollama_client()
            models = client.list()
            model_names = [m.get("name", m.get("model", "unknown")) for m in models.get("models", [])]
            return {
                "success": True,
                "message": f"Connected successfully, available models: {', '.join(model_names[:5])}",
                "model": self.model,
            }
        except Exception as exc:
            return {"success": False, "message": f"Ollama connection failed: {exc}", "model": self.model}

    def _test_openai_compatible(self) -> dict:
        try:
            url = f"{str(self.api_base).rstrip('/')}/chat/completions"
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key or 'sk-no-key'}",
            }
            payload = {
                "model": self.model,
                "messages": [{"role": "user", "content": "Hi"}],
                "max_tokens": 5,
            }

            response = requests.post(url, json=payload, headers=headers, timeout=self.test_timeout)

            if response.status_code == 200:
                return {"success": True, "message": "API connection successful", "model": self.model}
            if response.status_code == 401:
                return {"success": False, "message": "API key is invalid", "model": self.model}
            if response.status_code == 404:
                return {"success": False, "message": f"Model '{self.model}' does not exist", "model": self.model}

            try:
                error_msg = response.json().get("error", {}).get("message", response.text)
            except ValueError:
                error_msg = response.text
            return {
                "success": False,
                "message": f"API error ({response.status_code}): {error_msg}",
                "model": self.model,
            }
        except requests.exceptions.Timeout:
            return {"success": False, "message": "Connection timed out", "model": self.model}
        except requests.exceptions.ConnectionError:
            return {"success": False, "message": "Unable to connect to API service", "model": self.model}
        except Exception as exc:
            return {"success": False, "message": str(exc), "model": self.model}

    def _call_ollama(self, prompt: str, system_prompt: str | None = None) -> str:
        client = self._ollama_client()
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        response = client.chat(
            model=self.model,
            messages=messages,
            stream=False,
        )
        return response["message"]["content"]

    def _call_openai_compatible(self, prompt: str, system_prompt: str | None = None) -> str:
        url = f"{str(self.api_base).rstrip('/')}/chat/completions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key or 'sk-no-key'}",
        }

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.1,
            "max_tokens": self.request_max_tokens,
            "stream": False,
        }
        if self.provider in self.json_response_providers:
            payload["response_format"] = {"type": "json_object"}

        response = requests.post(url, json=payload, headers=headers, timeout=self.timeout)

        if self.verbose_http_errors:
            if response.status_code != 200:
                detail = response.text[:300].strip()
                raise RuntimeError(f"API request failed: HTTP {response.status_code} {detail}")
            if not response.text.strip():
                raise RuntimeError("API returned an empty response")
        else:
            response.raise_for_status()

        try:
            result = response.json()
        except ValueError as exc:
            raise RuntimeError(f"API returned non-JSON content: {response.text[:200]!r}") from exc

        choices = result.get("choices") or []
        if not choices:
            raise RuntimeError("API response missing choices")

        content = choices[0].get("message", {}).get("content") or choices[0].get("delta", {}).get("content")
        if not content:
            raise RuntimeError("API response missing message content")
        return content


def default_api_key_for_provider(provider: str) -> str | None:
    provider = provider.lower().strip()
    provider_env = {
        "openai": "OPENAI_API_KEY",
        "deepseek": "DEEPSEEK_API_KEY",
        "nvidia": "NVIDIA_API_KEY",
    }.get(provider)
    for key in ("SECFLOW_AI_API_KEY", provider_env):
        if key:
            value = os.getenv(key)
            if value:
                return value.strip()
    return None
