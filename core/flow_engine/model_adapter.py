from __future__ import annotations

import json
import warnings
from pathlib import Path
from typing import Any, Sequence


class PacketraModelAdapter:
    FEATURE_ALIASES = {
        "Source IP": "Src IP",
        "Source Port": "Src Port",
        "Destination IP": "Dst IP",
        "Destination Port": "Dst Port",
    }

    def __init__(
        self,
        model_path: str | None = None,
        feature_columns_path: str | None = None,
        label_encoder_path: str | None = None,
        scaler_path: str | None = None,
        model_info_path: str | None = None,
        feature_order: list[str] | None = None,
        fallback_labels: list[str] | None = None,
    ) -> None:
        self.model_path = Path(model_path).resolve() if model_path else None
        self.feature_columns_path = Path(feature_columns_path).resolve() if feature_columns_path else None
        self.label_encoder_path = Path(label_encoder_path).resolve() if label_encoder_path else None
        self.scaler_path = Path(scaler_path).resolve() if scaler_path else None
        self.model_info_path = Path(model_info_path).resolve() if model_info_path else None
        self.feature_order = [str(v).strip() for v in (feature_order or []) if str(v).strip()]
        self.fallback_labels = list(fallback_labels or [])

        self._model: Any = None
        self._np: Any = None
        self._torch: Any = None
        self._xgb: Any = None
        self._scaler: Any = None
        self._feature_columns: list[str] = []
        self._labels: list[str] = list(self.fallback_labels)
        self._is_xgb_booster = False
        self._is_torchscript = False
        self._model_info: dict[str, Any] = {}
        self._load_error: str | None = None

        if self.model_path:
            self._try_load()

    def _try_load(self) -> None:
        if not self.model_path or not self.model_path.exists():
            self._load_error = "model_not_found"
            return

        suffix = self.model_path.suffix.lower()
        if suffix == ".pt" or self.scaler_path or self.model_info_path:
            self._try_load_torchscript()
            return
        if suffix == ".json":
            self._try_load_xgboost_json()
            return

        try:
            import pickle

            with self.model_path.open("rb") as f:
                self._model = pickle.load(f)
            self._load_error = None
        except Exception:
            self._model = None
            self._load_error = "model_not_loaded"

    def _try_load_torchscript(self) -> None:
        try:
            import joblib
            import numpy as np
            import torch
        except Exception:
            self._load_error = "torch_not_available"
            return

        if not self.scaler_path or not self.scaler_path.exists():
            self._load_error = "scaler_not_found"
            return

        model_info: dict[str, Any] = {}
        if self.model_info_path and self.model_info_path.exists():
            try:
                with self.model_info_path.open("r", encoding="utf-8") as f:
                    loaded = json.load(f)
                if isinstance(loaded, dict):
                    model_info = loaded
            except Exception:
                model_info = {}

        labels = list(self.fallback_labels)
        if self.label_encoder_path and self.label_encoder_path.exists():
            try:
                encoder = joblib.load(self.label_encoder_path)
                classes_ = getattr(encoder, "classes_", None)
                if classes_ is not None:
                    labels = [str(v) for v in list(classes_)]
            except Exception:
                pass
        if not labels:
            classes = model_info.get("classes")
            if isinstance(classes, list) and classes:
                labels = [str(v) for v in classes]

        feature_columns: list[str] = list(self.feature_order)
        if not feature_columns and self.feature_columns_path and self.feature_columns_path.exists():
            try:
                with self.feature_columns_path.open("r", encoding="utf-8") as f:
                    rows = json.load(f)
                if isinstance(rows, list):
                    feature_columns = [str(v).strip() for v in rows if str(v).strip()]
            except Exception:
                feature_columns = []
        if not feature_columns:
            self._load_error = "feature_columns_not_found"
            return

        expected = int(model_info.get("num_features", 0) or 0)
        if expected > 0 and len(feature_columns) != expected:
            self._load_error = "feature_count_mismatch"
            return

        try:
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", category=DeprecationWarning, message=r".*torch\.jit\.load.*")
                self._model = torch.jit.load(str(self.model_path), map_location="cpu")
            self._model.eval()
            self._scaler = joblib.load(self.scaler_path)
            self._torch = torch
            self._np = np
            self._feature_columns = feature_columns
            self._labels = labels
            self._model_info = model_info
            self._is_torchscript = True
            self._load_error = None
        except Exception:
            self._model = None
            self._scaler = None
            self._load_error = "torchscript_model_not_loaded"

    def _try_load_xgboost_json(self) -> None:
        try:
            import numpy as np
            import xgboost as xgb
        except Exception:
            self._load_error = "xgboost_not_available"
            return

        feature_columns: list[str] = list(self.feature_order)
        if not feature_columns and self.feature_columns_path and self.feature_columns_path.exists():
            try:
                with self.feature_columns_path.open("r", encoding="utf-8") as f:
                    rows = json.load(f)
                if isinstance(rows, list):
                    feature_columns = [str(v).strip() for v in rows if str(v).strip()]
            except Exception:
                feature_columns = []
        if not feature_columns:
            self._load_error = "feature_columns_not_found"
            return
        expected = 0
        if self.model_info_path and self.model_info_path.exists():
            try:
                with self.model_info_path.open("r", encoding="utf-8") as f:
                    loaded = json.load(f)
                if isinstance(loaded, dict):
                    expected = int(loaded.get("num_features", 0) or 0)
            except Exception:
                expected = 0
        if expected > 0 and len(feature_columns) != expected:
            self._load_error = "feature_count_mismatch"
            return

        labels = list(self.fallback_labels)
        if self.label_encoder_path and self.label_encoder_path.exists():
            try:
                import joblib

                encoder = joblib.load(self.label_encoder_path)
                classes_ = getattr(encoder, "classes_", None)
                if classes_ is not None:
                    labels = [str(v) for v in list(classes_)]
            except Exception:
                pass

        try:
            booster = xgb.Booster()
            booster.load_model(str(self.model_path))
            self._model = booster
            self._xgb = xgb
            self._np = np
            self._feature_columns = feature_columns
            self._labels = labels
            self._is_xgb_booster = True
            self._load_error = None
        except Exception:
            self._load_error = "xgboost_model_not_loaded"

    @property
    def loaded(self) -> bool:
        return self._model is not None

    def _to_float(self, value: Any) -> float:
        try:
            if value is None:
                return 0.0
            if isinstance(value, bool):
                return 1.0 if value else 0.0
            if isinstance(value, str):
                text = value.strip()
                if not text:
                    return 0.0
                if text.lower() in {"inf", "+inf", "infinity", "+infinity", "-inf", "-infinity", "nan", "+nan", "-nan"}:
                    return 0.0
                return float(text.replace(",", ""))
            return float(value)
        except Exception:
            return 0.0

    def _dict_value(self, item: dict[str, Any], col: str) -> Any:
        if col in item:
            return item.get(col, 0.0)
        alias = self.FEATURE_ALIASES.get(col)
        if alias and alias in item:
            return item.get(alias, 0.0)
        return 0.0

    def _normalize_matrix(self, features: list[Any]) -> list[list[float]] | str:
        if not features:
            return []

        first = features[0]
        if isinstance(first, dict):
            if not self._feature_columns:
                return "feature_columns_not_found"
            matrix: list[list[float]] = []
            for item in features:
                row = [self._to_float(self._dict_value(item, col)) for col in self._feature_columns]
                matrix.append(row)
            return matrix

        if isinstance(first, (list, tuple)):
            matrix = []
            for item in features:
                matrix.append([self._to_float(v) for v in item])
            return matrix

        try:
            import numpy as np

            arr = np.asarray(features, dtype=float)
            if arr.ndim == 1:
                arr = arr.reshape(1, -1)
            return arr.tolist()
        except Exception:
            return "model_input_not_supported"

    def _predict_torchscript(self, features: list[Any]) -> list[dict[str, Any]] | str:
        matrix = self._normalize_matrix(features)
        if isinstance(matrix, str):
            return matrix
        if not matrix:
            return []

        np = self._np
        torch = self._torch

        try:
            X = np.asarray(matrix, dtype=np.float32)
            X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
            X = self._scaler.transform(X)
            X = np.asarray(X, dtype=np.float32)
            X_tensor = torch.from_numpy(X)
            with torch.no_grad():
                logits = self._model(X_tensor)
                if isinstance(logits, (tuple, list)):
                    logits = logits[0]
                probabilities = torch.softmax(logits, dim=1)
                pred_ids = torch.argmax(probabilities, dim=1).cpu().numpy()
                pred_probs = torch.max(probabilities, dim=1).values.cpu().numpy()

            out: list[dict[str, Any]] = []
            for idx, prob in zip(pred_ids, pred_probs):
                class_idx = int(idx)
                confidence = float(prob)
                label = self._labels[class_idx] if 0 <= class_idx < len(self._labels) else str(class_idx)
                out.append(
                    {
                        "prediction": str(label),
                        "label": str(label),
                        "anomaly_score": confidence,
                        "confidence": confidence,
                        "class_index": class_idx,
                    }
                )
            return out
        except Exception:
            return "model_predict_failed"

    def predict(self, features: list[Any]) -> list[dict[str, Any]] | str | None:
        if self._model is None:
            return self._load_error or "model_not_loaded"
        try:
            if self._is_torchscript:
                return self._predict_torchscript(features)

            if self._is_xgb_booster:
                if not self._feature_columns:
                    return "feature_columns_not_found"
                matrix: list[list[float]] = []
                for item in features:
                    if isinstance(item, dict):
                        row = [self._to_float(self._dict_value(item, col)) for col in self._feature_columns]
                    else:
                        row = [self._to_float(v) for v in item]
                    matrix.append(row)
                dmatrix = self._xgb.DMatrix(
                    self._np.asarray(matrix, dtype=float),
                    feature_names=self._feature_columns,
                )
                raw_pred = self._model.predict(dmatrix)
                out: list[dict[str, Any]] = []
                for pred in raw_pred:
                    arr = self._np.asarray(pred)
                    if arr.ndim == 0:
                        class_idx = int(round(float(arr)))
                        confidence = 1.0
                    else:
                        class_idx = int(arr.argmax())
                        confidence = float(arr[class_idx])
                    label = self._labels[class_idx] if 0 <= class_idx < len(self._labels) else str(class_idx)
                    out.append(
                        {
                            "prediction": str(label),
                            "label": str(label),
                            "anomaly_score": confidence,
                            "confidence": confidence,
                            "class_index": class_idx,
                        }
                    )
                return out

            rows = []
            for item in features:
                if isinstance(item, dict):
                    rows.append([v for _, v in sorted(item.items(), key=lambda kv: kv[0])])
                else:
                    rows.append([v for v in item])
            if hasattr(self._model, "predict_proba"):
                pred = self._model.predict_proba(rows)
                label = self._model.predict(rows)
                out = []
                for i, lv in enumerate(label):
                    score = float(max(pred[i])) if i < len(pred) else 0.0
                    out.append(
                        {
                            "prediction": str(lv),
                            "label": str(lv),
                            "anomaly_score": score,
                            "confidence": score,
                        }
                    )
                return out
            if hasattr(self._model, "predict"):
                label = self._model.predict(rows)
                return [
                    {
                        "prediction": str(v),
                        "label": str(v),
                        "anomaly_score": 0.0,
                        "confidence": 0.0,
                    }
                    for v in label
                ]
            return "model_not_supported"
        except Exception:
            return "model_predict_failed"
