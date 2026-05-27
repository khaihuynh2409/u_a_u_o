"""
==============================================================================
 C&C SERVER DETECTION TOOL - Module: Bi-LSTM DGA Detector
 Mô tả: Phát hiện tên miền được tạo bởi Domain Generation Algorithm (DGA)
         sử dụng mạng nơ-ron Bi-directional LSTM.
==============================================================================
"""
import numpy as np
import os
import re
import math
from pathlib import Path

MODEL_PATH = Path(__file__).parent.parent / "models" / "bilstm_dga_model.keras"
CHAR_MAP_PATH = Path(__file__).parent.parent / "models" / "char_map.npy"

# Tập ký tự hợp lệ cho tên miền
VALID_CHARS = list("abcdefghijklmnopqrstuvwxyz0123456789-.")
MAX_LEN = 64  # Độ dài tối đa của chuỗi tên miền

# Danh sách domain hợp lệ nổi tiếng (whitelist)
ALEXA_WHITELIST = {
    "google.com", "youtube.com", "facebook.com", "amazon.com", "microsoft.com",
    "apple.com", "netflix.com", "twitter.com", "instagram.com", "linkedin.com",
    "github.com", "stackoverflow.com", "reddit.com", "wikipedia.org", "zoom.us",
    "dropbox.com", "cloudflare.com", "akamai.com", "fastly.com", "office.com",
    "windows.com", "bing.com", "live.com", "hotmail.com", "outlook.com",
    "yahoo.com", "gmail.com", "drive.google.com", "maps.google.com",
    "play.google.com", "accounts.google.com", "update.microsoft.com",
    "windowsupdate.com", "adobe.com", "mozilla.org", "firefox.com",
}


class DGADetector:
    """
    Phát hiện DGA domain bằng mô hình Bi-LSTM.
    Kết hợp với phân tích lexical (entropy, tỉ lệ ký tự số, độ dài).
    """

    def __init__(self):
        self.model = None
        self.char_to_idx = {}
        self._loaded = False

    def _check_system_support(self):
        import sys
        import os
        import subprocess

        # Trên Linux/Mac, TensorFlow luôn hỗ trợ (không cần kiểm tra AVX qua WinAPI)
        if sys.platform != 'win32':
            try:
                check_script = (
                    "import os; os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'; "
                    "import tensorflow"
                )
                result = subprocess.run(
                    [sys.executable, "-c", check_script],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=15
                )
                return result.returncode == 0
            except Exception:
                return False

        import ctypes
        try:
            # 1. Kiểm tra AVX (TensorFlow 2.x yêu cầu tối thiểu AVX)
            # PF_AVX_INSTRUCTIONS_AVAILABLE = 17
            if ctypes.windll.kernel32.IsProcessorFeaturePresent(17) == 0:
                return False
                
            # 2. Kiểm tra import an toàn
            python_exe = sys.executable
            pythonw_exe = os.path.join(os.path.dirname(sys.executable), 'pythonw.exe')
            if os.path.exists(pythonw_exe):
                python_exe = pythonw_exe
            
            check_script = (
                "import sys, ctypes; "
                "ctypes.windll.kernel32.SetErrorMode(0x0001 | 0x0002 | 0x8000); "
                "import os; os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'; "
                "import tensorflow"
            )
            
            # Use DETACHED_PROCESS (0x00000008) and CREATE_NO_WINDOW (0x08000000)
            flags = 0x08000000 | 0x00000008

            result = subprocess.run(
                [python_exe, "-c", check_script],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                creationflags=flags,
                timeout=15
            )
            return result.returncode == 0
        except Exception:
            return False

    def load(self):
        """Tải mô hình Bi-LSTM từ file."""
        if self._loaded:
            return True
        try:
            # Tạo char mapping
            self.char_to_idx = {ch: i + 1 for i, ch in enumerate(VALID_CHARS)}
            self.char_to_idx['<UNK>'] = len(self.char_to_idx) + 1

            if MODEL_PATH.exists():
                tf_supported = self._check_system_support()
                
                if not tf_supported:
                    raise ImportError("TensorFlow not supported on this CPU")
                    
                import tensorflow as tf
                self.model = tf.keras.models.load_model(str(MODEL_PATH))
                self._loaded = True
            else:
                self._create_demo_model()
            return True
        except Exception:
            self._use_heuristic_only()
            return True

    def _create_demo_model(self):
        """
        Tạo và huấn luyện mô hình Bi-LSTM demo.
        Kiến trúc: Embedding -> Bi-LSTM -> Dropout -> Dense
        """
        try:
            tf_supported = self._check_system_support()
                
            if not tf_supported:
                raise ImportError("TensorFlow not supported on this CPU")

            import tensorflow as tf
            from tensorflow.keras.models import Sequential
            from tensorflow.keras.layers import (
                Embedding, Bidirectional, LSTM,
                SpatialDropout1D, Dense, Dropout
            )

            vocab_size = len(self.char_to_idx) + 2

            # Kiến trúc Bi-LSTM với Spatial Dropout chống overfitting
            self.model = Sequential([
                Embedding(vocab_size, 64, input_length=MAX_LEN, mask_zero=True),
                SpatialDropout1D(0.3),
                Bidirectional(LSTM(128, return_sequences=True, dropout=0.2, recurrent_dropout=0.2)),
                Bidirectional(LSTM(64, dropout=0.2)),
                Dense(64, activation='relu'),
                Dropout(0.4),
                Dense(1, activation='sigmoid')
            ])

            self.model.compile(
                optimizer='adam',
                loss='binary_crossentropy',
                metrics=['accuracy']
            )

            # Tạo dữ liệu huấn luyện giả lập
            benign_domains = [
                "google", "youtube", "facebook", "amazon", "microsoft",
                "apple", "netflix", "github", "stackoverflow", "cloudflare",
                "update", "windows", "office", "mozilla", "firefox",
                "dropbox", "instagram", "twitter", "linkedin", "reddit",
                "mail", "smtp", "pop", "imap", "cdn",
            ] * 100

            # DGA domains (giả lập - chuỗi ngẫu nhiên cao entropy)
            dga_domains = []
            for _ in range(100):
                length = np.random.randint(12, 32)
                dga = ''.join(np.random.choice(list("abcdefghijklmnopqrstuvwxyz0123456789"), length))
                dga_domains.append(dga)

            all_domains = benign_domains + dga_domains
            labels = [0] * len(benign_domains) + [1] * len(dga_domains)

            # Tokenization
            X = self._tokenize_batch(all_domains)
            y = np.array(labels)

            # Huấn luyện nhanh cho demo
            self.model.fit(
                X, y,
                epochs=1,
                batch_size=64,
                validation_split=0.2,
                verbose=0
            )

            # Lưu mô hình
            MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
            self.model.save(str(MODEL_PATH))
            self._loaded = True
            # print("[DGADetector] Đã tạo và lưu mô hình Bi-LSTM demo.")

        except Exception:
            self._use_heuristic_only()

    def _use_heuristic_only(self):
        """Fallback: chỉ dùng heuristic nếu không có TensorFlow."""
        self.model = None
        self._loaded = True

    def _tokenize(self, domain: str) -> np.ndarray:
        """Chuyển đổi chuỗi tên miền thành chuỗi số (tokenization)."""
        # Chỉ lấy phần hostname, bỏ TLD
        hostname = domain.lower().split('.')[0]
        tokens = [self.char_to_idx.get(c, self.char_to_idx['<UNK>']) for c in hostname[:MAX_LEN]]
        # Padding
        padded = tokens + [0] * (MAX_LEN - len(tokens))
        return np.array(padded[:MAX_LEN])

    def _tokenize_batch(self, domains: list) -> np.ndarray:
        return np.array([self._tokenize(d) for d in domains])

    def _calculate_entropy(self, s: str) -> float:
        """Tính Shannon entropy của chuỗi."""
        if not s:
            return 0.0
        prob = [float(s.count(c)) / len(s) for c in set(s)]
        return -sum(p * math.log2(p) for p in prob if p > 0)

    def _lexical_analysis(self, domain: str) -> dict:
        """Phân tích lexical của tên miền."""
        # Tách hostname
        parts = domain.lower().split('.')
        hostname = parts[0] if parts else domain

        entropy = self._calculate_entropy(hostname)
        digit_ratio = sum(c.isdigit() for c in hostname) / max(len(hostname), 1)
        consonant_ratio = sum(c in 'bcdfghjklmnpqrstvwxyz' for c in hostname) / max(len(hostname), 1)
        length = len(hostname)
        unique_chars = len(set(hostname))
        char_diversity = unique_chars / max(length, 1)

        # Heuristic scoring
        score = 0
        reasons = []

        if entropy > 3.5:
            score += 30
            reasons.append(f"Entropy cao ({entropy:.2f})")
        if digit_ratio > 0.3:
            score += 20
            reasons.append(f"Tỉ lệ số cao ({digit_ratio:.1%})")
        if length > 20:
            score += 15
            reasons.append(f"Tên miền dài ({length} ký tự)")
        if consonant_ratio > 0.7:
            score += 15
            reasons.append("Nhiều phụ âm liên tiếp")
        if char_diversity > 0.7:
            score += 10
            reasons.append("Ký tự phân tán cao")
        if re.search(r'\d{4,}', hostname):
            score += 10
            reasons.append("Chuỗi số dài")

        return {
            "entropy": entropy,
            "digit_ratio": digit_ratio,
            "consonant_ratio": consonant_ratio,
            "length": length,
            "char_diversity": char_diversity,
            "heuristic_score": min(score, 100),
            "reasons": reasons
        }

    def predict(self, domain: str) -> dict:
        """
        Dự đoán domain có phải DGA không.
        Kết hợp Bi-LSTM + Heuristic để tăng độ chính xác.
        """
        if not self._loaded:
            self.load()

        # Kiểm tra whitelist
        domain_clean = domain.lower().strip()
        base_domain = '.'.join(domain_clean.split('.')[-2:]) if '.' in domain_clean else domain_clean
        if base_domain in ALEXA_WHITELIST:
            return {
                "domain": domain,
                "is_dga": False,
                "label": "BENIGN (Whitelist)",
                "dl_confidence": 0.0,
                "heuristic_score": 0.0,
                "final_score": 0.0,
                "lexical": {},
                "whitelisted": True
            }

        # Phân tích lexical
        lexical = self._lexical_analysis(domain_clean)

        # Deep Learning prediction
        dl_score = 0.0
        if self.model is not None:
            try:
                X = self._tokenize(domain_clean).reshape(1, -1)
                dl_score = float(self.model.predict(X, verbose=0)[0][0])
            except Exception as e:
                print(f"[DGADetector] Lỗi DL predict: {e}")

        # Kết hợp điểm số
        heuristic_norm = lexical["heuristic_score"] / 100.0
        if self.model is not None:
            final_score = (dl_score * 0.65 + heuristic_norm * 0.35) * 100
        else:
            final_score = lexical["heuristic_score"]

        is_dga = final_score >= 50

        return {
            "domain": domain,
            "is_dga": is_dga,
            "label": "DGA (Nguy hiểm)" if is_dga else "BENIGN",
            "dl_confidence": dl_score * 100,
            "heuristic_score": lexical["heuristic_score"],
            "final_score": final_score,
            "lexical": lexical,
            "whitelisted": False
        }

    def analyze_dns_stream(self, domains: list) -> dict:
        """Phân tích một luồng truy vấn DNS để phát hiện DGA burst."""
        results = [self.predict(d) for d in domains]
        dga_count = sum(1 for r in results if r["is_dga"])
        dga_ratio = dga_count / max(len(domains), 1)

        return {
            "total": len(domains),
            "dga_count": dga_count,
            "dga_ratio": dga_ratio,
            "is_dga_burst": dga_ratio > 0.3,
            "results": results
        }
