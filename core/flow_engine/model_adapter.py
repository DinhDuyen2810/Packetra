from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class PacketraModelAdapter:
    def __init__(
        self,
        model_path: str | None = None,
        feature_columns_path: str | None = None,
        label_encoder_path: str | None = None,
        fallback_labels: list[str] | None = None,
    ) -> None:
        self.model_path = Path(model_path).resolve() if model_path else None
        self.feature_columns_path = Path(feature_columns_path).resolve() if feature_columns_path else None
        self.label_encoder_path = Path(label_encoder_path).resolve() if label_encoder_path else None
        self.fallback_labels = list(fallback_labels or [])
        self._model: Any = None
        self._xgb: Any = None
        self._np: Any = None
        self._feature_columns: list[str] = []
        self._labels: list[str] = list(self.fallback_labels)
        self._is_xgb_booster = False
        self._load_error: str | None = None
        if self.model_path:
            self._try_load()

    def _try_load(self) -> None:
        if not self.model_path or not self.model_path.exists():
            self._load_error = "model_not_found"
            return
        suffix = self.model_path.suffix.lower()
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

    def _try_load_xgboost_json(self) -> None:
        try:
            import numpy as np
            import xgboost as xgb
        except Exception:
            self._load_error = "xgboost_not_available"
            return

        feature_columns: list[str] = []
        if self.feature_columns_path and self.feature_columns_path.exists():
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

        labels = list(self.fallback_labels)
        if self.label_encoder_path and self.label_encoder_path.exists():
            try:
                import pickle

                with self.label_encoder_path.open("rb") as f:
                    encoder = pickle.load(f)
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
            return float(value)
        except Exception:
            return 0.0

    def predict(self, features: list[dict[str, Any]]) -> list[dict[str, Any]] | str | None:
        if self._model is None:
            return self._load_error or "model_not_loaded"
        try:
            if self._is_xgb_booster:
                if not self._feature_columns:
                    return "feature_columns_not_found"
                matrix: list[list[float]] = []
                for item in features:
                    row = [self._to_float(item.get(col, 0.0)) for col in self._feature_columns]
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
                    out.append({"prediction": str(label), "anomaly_score": confidence})
                return out

            rows = []
            for item in features:
                rows.append([v for _, v in sorted(item.items(), key=lambda kv: kv[0])])
            if hasattr(self._model, "predict_proba"):
                pred = self._model.predict_proba(rows)
                label = self._model.predict(rows)
                out = []
                for i, lv in enumerate(label):
                    score = float(max(pred[i])) if i < len(pred) else 0.0
                    out.append({"prediction": str(lv), "anomaly_score": score})
                return out
            if hasattr(self._model, "predict"):
                label = self._model.predict(rows)
                return [{"prediction": str(v), "anomaly_score": 0.0} for v in label]
            return "model_not_supported"
        except Exception:
            return "model_predict_failed"
