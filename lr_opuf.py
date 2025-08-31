import numpy as np
from hashlib import sha256
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from preprocessing import PUFs, get_parity_vectors2

# —— Consistent with MoPE —— 
STAGES = 64
K_XOR  = 7
PUF_SEED = 123
CRP_SEED = 45
N = 3000000         # You can start with 60,000 sprints; eventually you can change back to 3,000,000

# Generation of synthetic CRPs homologous to MoPE
pufs = PUFs(stages=STAGES)
pufs.seed = PUF_SEED
pufs.add_XOR_PUF(k=K_XOR, num=1)
c, responses = pufs.generate_crps(CRP_SEED, N)
c = get_parity_vectors2(c)
y = np.array(responses, dtype=np.int8).reshape(-1)

# Segmentation
X_tr, X_te, y_tr, y_te = train_test_split(c, y, test_size=0.2, random_state=42)

# Lightweight attacker (only used to get predicted responses)
clf = LogisticRegression(max_iter=1000, n_jobs=-1)
clf.fit(X_tr, y_tr)
y_pred = clf.predict(X_te)

# —— lr_opuf: Same logic function as LR-OPUF.py —— 
class LrOpufModule:
    def __init__(self, S: bytes, C: bytes):
        self.S, self.C = S, C
    def tf1(self, C: bytes, S: bytes) -> bytes:
        return sha256(C + S).digest()
    def fuzzy_extract_gen(self, R_prime: bytes):
        return R_prime[:16], R_prime[16:32]
    def tf2(self, K: bytes, S: bytes) -> bytes:
        return sha256(S + K).digest()[:16]
    def response_to_Q(self, r_bit: int) -> bytes:
        W = self.tf1(self.C, self.S)
        R_prime = sha256(bytes([int(r_bit)]) + W).digest()[:32]
        K, _ = self.fuzzy_extract_gen(R_prime)
        return self.tf2(K, self.S)

# Calculating Q hit rate (anti-modeling indicator)
lro = LrOpufModule(S=b"SESSION_STATE_2025", C=b"PUBLIC_SALT_XX")
Q_true = [lro.response_to_Q(int(b)) for b in y_te]
Q_pred = [lro.response_to_Q(int(b)) for b in y_pred]
acc_Q = np.mean([a == b for a, b in zip(Q_true, Q_pred)])

# —— Output ——
print(f"[LR-OPUF] Q_match={acc_Q:.4f}")