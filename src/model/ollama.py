from __future__ import annotations
import copy
import os
import time
import subprocess
from typing import Any, Dict, Optional, Tuple

try:
    import ollama
    _HAS_OLLAMA_PY = True
except Exception:
    _HAS_OLLAMA_PY = False
    try:
        import requests
    except Exception as e:
        raise RuntimeError("Missing ollama client. Install `pip install ollama` or ensure `requests` is available.") from e

_MODEL_NAME_MAP: Dict[str, str] = {
    "ollama-deepseek-8b-q4": "deepseek-r1:8b-llama-distill-q4_K_M",
    "ollama-deepseek-1.5b-q4": "deepseek-r1:1.5b-qwen-distill-q4_K_M",
    "ollama-qwen-1.7b": "qwen3:1.7b",
    "ollama-qwen-8b": "qwen3:8b",
    "ollama-gpt-oss": "gpt-oss",
}

_OLLAMA_DEFAULT_OPTIONS: Dict[str, Any] = {
    "temperature": 0.8,
    "num_predict": -1,
    "stop": None,
    "seed": 0,
}

def _normalize_key(name: str) -> str:
    return (name or "").strip().lower()

def _resolve_model(name: str) -> str:
    return _MODEL_NAME_MAP.get(_normalize_key(name), name)

class OllamaModel:
    def __init__(self, model_name: str, **kwargs: Any) -> None:
        self.model = _resolve_model(model_name)
        self.temperature: float = float(kwargs.get("temperature", 0.0))
        self.max_output_tokens: Optional[int] = kwargs.get("max_output_tokens", None)
        self.top_p: Optional[float] = kwargs.get("top_p", None)
        self.top_k: Optional[int] = kwargs.get("top_k", None)
        self.response_mime_type: str = kwargs.get("response_mime_type", "text/plain")
        self.auto_start: bool = bool(kwargs.get("auto_start", True))
        self.auto_pull: bool = bool(kwargs.get("auto_pull", True))
        self.verbose: bool = bool(kwargs.get("verbose", True))
        self._host: str = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
        user_opts: Dict[str, Any] = kwargs.get("ollama_options", {}) or {}
        self._base_options: Dict[str, Any] = copy.deepcopy(_OLLAMA_DEFAULT_OPTIONS)
        self._base_options.update(user_opts)
        if "temperature" not in user_opts or user_opts.get("temperature") is None:
            self._base_options["temperature"] = self.temperature if self.temperature is not None else _OLLAMA_DEFAULT_OPTIONS["temperature"]
        if self.top_p is not None and "top_p" not in self._base_options:
            self._base_options["top_p"] = float(self.top_p)
        if self.top_k is not None and "top_k" not in self._base_options:
            self._base_options["top_k"] = int(self.top_k)
        self.supports_cache: bool = False
        self._ensure_server_ready()
        self._ensure_model_present()

    def _is_server_up(self) -> bool:
        try:
            if _HAS_OLLAMA_PY:
                ollama.list()
                return True
            else:
                import requests
                r = requests.get(f"{self._host}/api/tags", timeout=2)
                return r.ok
        except Exception:
            return False

    def _start_server(self) -> None:
        if not (self._host.endswith("127.0.0.1:11434") or self._host.endswith("localhost:11434")):
            return
        try:
            if self.verbose:
                print("[OllamaModel] Starting local Ollama server (background)...")
            subprocess.Popen(
                ["ollama", "serve"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except Exception:
            started = False
            try:
                subprocess.run(["brew", "services", "start", "ollama"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                started = True
            except Exception:
                pass
            if not started:
                try:
                    subprocess.run(["systemctl", "--user", "start", "ollama"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except Exception:
                    pass

    def _ensure_server_ready(self) -> None:
        if self._is_server_up():
            return
        if not self.auto_start:
            raise RuntimeError(f"Ollama server not reachable at {self._host}. Set auto_start=True or start server manually.")
        self._start_server()
        while not self._is_server_up():
            if self.verbose:
                print("[OllamaModel] Waiting for server...")
            time.sleep(1)

    def _model_exists(self) -> bool:
        try:
            if _HAS_OLLAMA_PY:
                try:
                    ollama.show(self.model)
                    return True
                except Exception:
                    return False
            else:
                import requests
                resp = requests.get(f"{self._host}/api/tags", timeout=10)
                resp.raise_for_status()
                data = resp.json() or {}
                models = data.get("models", []) or []
                names = {m.get("name") for m in models if isinstance(m, dict)}
                return self.model in names
        except Exception:
            return False

    def _pull_model(self) -> None:
        if _HAS_OLLAMA_PY:
            if self.verbose:
                print(f"[OllamaModel] Pulling model `{self.model}` ...")
            ollama.pull(self.model, stream=False)
        else:
            import requests
            if self.verbose:
                print(f"[OllamaModel] Pulling model `{self.model}` via HTTP ...")
            payload = {"name": self.model, "stream": False}
            r = requests.post(f"{self._host}/api/pull", json=payload, timeout=None)
            r.raise_for_status()

    def _ensure_model_present(self) -> None:
        if self._model_exists():
            return
        if not self.auto_pull:
            raise RuntimeError(f"Model `{self.model}` is not installed. Set auto_pull=True or run `ollama pull {self.model}`.")
        self._pull_model()
        while not self._model_exists():
            if self.verbose:
                print("[OllamaModel] Waiting for model to be ready...")
            time.sleep(1)

    def _resolved_options(self, config_override: Any) -> Dict[str, Any]:
        opts = copy.deepcopy(self._base_options)
        explicit_max: Optional[int] = None
        try:
            if isinstance(config_override, dict):
                explicit_max = config_override.get("max_output_tokens", None)
            elif hasattr(config_override, "max_output_tokens"):
                explicit_max = getattr(config_override, "max_output_tokens")
        except Exception:
            explicit_max = None
        if explicit_max is not None:
            opts["num_predict"] = int(explicit_max) if int(explicit_max) > 0 else -1
        elif self.max_output_tokens is not None:
            opts["num_predict"] = int(self.max_output_tokens) if int(self.max_output_tokens) > 0 else -1
        if isinstance(config_override, dict):
            if "temperature" in config_override and config_override["temperature"] is not None:
                opts["temperature"] = float(config_override["temperature"])
            if "top_p" in config_override and config_override["top_p"] is not None:
                opts["top_p"] = float(config_override["top_p"])
            if "top_k" in config_override and config_override["top_k"] is not None:
                opts["top_k"] = int(config_override["top_k"])
        return opts

    def _generate_with_py(self, prompt: str, options: Dict[str, Any]) -> Dict[str, Any]:
        res = ollama.generate(model=self.model, prompt=prompt, options=options)
        text = res.get("response", "")
        usage = {
            "prompt_tokens": res.get("prompt_eval_count"),
            "output_tokens": res.get("eval_count"),
            "total_tokens": (res.get("prompt_eval_count", 0) or 0) + (res.get("eval_count", 0) or 0),
        }
        return {"text": text, "usage": usage, "raw": res}

    def _generate_with_http(self, prompt: str, options: Dict[str, Any]) -> Dict[str, Any]:
        import requests
        payload = {"model": self.model, "prompt": prompt, "stream": False, "options": options}
        res = requests.post(f"{self._host}/api/generate", json=payload, timeout=None)
        res.raise_for_status()
        data = res.json()
        text = data.get("response", "")
        usage = {
            "prompt_tokens": data.get("prompt_eval_count"),
            "output_tokens": data.get("eval_count"),
            "total_tokens": (data.get("prompt_eval_count", 0) or 0) + (data.get("eval_count", 0) or 0),
        }
        return {"text": text, "usage": usage, "raw": data}

    def _generate(self, prompt: str, options: Dict[str, Any]) -> Dict[str, Any]:
        if not self._is_server_up():
            self._ensure_server_ready()
        if not self._model_exists():
            self._ensure_model_present()
        if _HAS_OLLAMA_PY:
            return self._generate_with_py(prompt, options)
        return self._generate_with_http(prompt, options)

    @staticmethod
    def _combine_prompt(system_prompt: str, user_prompt: str, few_shot_examples: Optional[str]) -> str:
        if few_shot_examples:
            return f"{system_prompt}\n\n{few_shot_examples}\n\n{user_prompt}".strip()
        return f"{system_prompt}\n\n{user_prompt}".strip() if system_prompt else (user_prompt or "")

    def invoke(
        self,
        system_prompt: str,
        user_prompt: str,
        few_shot_examples: Optional[str] = None,
        *,
        config_override: Any = None,
        contents_override: Any = None,
    ) -> Tuple[str, str, Dict[str, Optional[int]]]:
        combined = self._combine_prompt(system_prompt, user_prompt, few_shot_examples)
        options = self._resolved_options(config_override)
        out = self._generate(combined, options)
        return out["text"], "ollama", out["usage"]

    def call_model_with_rotation(self, *args, **kwargs):
        return self.invoke(*args, **kwargs)

    def call_gemini_with_rotation(self, *args, **kwargs):
        return self.invoke(*args, **kwargs)

    def predict(
        self,
        combined_prompt: str,
        return_usage: bool = False,
        *,
        config_override: Any = None,
        contents_override: Any = None,
    ):
        options = self._resolved_options(config_override)
        out = self._generate(combined_prompt, options)
        return out if return_usage else out["text"]