import hashlib
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from pypuf.simulation import ArbiterPUF, XORArbiterPUF
from pypuf.io import random_inputs
import numpy as np

# Defining custom exceptions
class AuthenticationFailed(Exception):
    """Exception thrown when authentication fails"""
    pass


# === Hash and Utility Functions ===
def h(data: bytes) -> bytes:
    """SHA-256 hash (h function in the scheme)"""
    return hashlib.sha256(data).digest()

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """Byte XOR (⊕ operation in the scheme)"""
    return bytes(x ^ y for x, y in zip(a, b))

def generate_nonce(length=16):
    """Generate random numbers (N_i, N_s in the scheme)"""
    return secrets.token_bytes(length)

class LrOpufModule:
    """LR-OPUF hardware module (PUF components)"""
    def __init__(self, state: bytes, challenge: bytes):
        # S_i, C_i in the scheme
        self.S = state
        self.C = challenge
        self.puf = ArbiterPUF(n=64, seed=42)  # 64-bit arbiter PUF
        self.K = None  # K_i in the scheme
        self.Q = None  # Q_i in the scheme
        self.R = None  # R_i in the scheme
        self.W = None  # W_i in the scheme

    def tf1(self, C, S):
        """Input Transformation (TF1 in the scheme)"""
        return h(C + S)  # W_i = h(C_i || S_i)

    def tf2(self, K, S):
        """Input Transformation (TF2 in the scheme)"""
        return h(S + K)  # Q_i = h(S_i || K_i)

    def fuzzy_extract_gen(self, R: bytes):
        """Fuzzy extractor generation (FE.Gen in the scheme)"""
        return R[:16], R[16:]  # K_i = First 16 bytes, hd_i = Last 16 bytes

    def simulate_puf(self, W: bytes) -> bytes:
        """PUF simulation (P in the scheme)"""
        # Converting W_i to 64 bits challenge
        bits_str = ''.join(f'{byte:08b}' for byte in W[:8])
        bit_array = np.array([[int(b) for b in bits_str]], dtype=np.int8)
        
        # PUF evaluation
        response = self.puf.eval(bit_array)  # return ±1
        
        # Convert the response to bits (Response bit in the scheme)
        response_bit = 1 if response[0] > 0 else 0
        
        # Expanded to 32-byte response
        return h(bytes([response_bit]) + W)[:32]

    def evaluate(self):
        """Complete PUF evaluation process (calculation process in the scheme)"""
        self.W = self.tf1(self.C, self.S)  # W_i = TF1(C_i, S_i)
        self.R = self.simulate_puf(self.W)  # R_i' = P(W_i)
        self.K, self.hd = self.fuzzy_extract_gen(self.R)  # K_i = FE.Rec(R_i')
        self.Q = self.tf2(self.K, self.S)  # Q_i = TF2(K_i)
        return self.Q

    def reconfigure(self):
        """Reconfigure (Reconfig in the scheme)"""
        self.S = h(self.S + self.R)  # S_{i+1} = h(S_i || R_i')
        self.C = h(self.C + self.S)  # C_{i+1} = h(C_i || S_{i+1})
        return self.S, self.C

class Device:
    """Device-side implementation"""
    def __init__(self, initial_state, initial_challenge):
        self.module = LrOpufModule(initial_state, initial_challenge)
        self.module.evaluate()  # Initial Assessment
        
        # Device status in the scheme
        self.current_Q = self.module.Q
        self.current_K = self.module.K
        self.RID = secrets.token_bytes(16)  # Device identifier
        self.current_nonce = None  # N_i in the scheme
        self.current_Q_star = None  # Save received Q*

    def initiate_authentication(self):
        """Initiate authentication (MSC₁ = {N_i})"""
        self.current_nonce = generate_nonce(16)
        return self.current_nonce

    def process_server_response(self, server_msg):
        """Processing server responses (MSC₂ = {N_s^*, Q^*, Π1})"""
        N_s_star, Q_star, Pi1 = server_msg
        self.current_Q_star = Q_star  # Save Q* for subsequent calculations
        
        # N_s = K_i ⊕ N_s^* in the scheme
        N_s = xor_bytes(N_s_star, self.current_K)
        
        # verify Π1 = h(N_s || K_i || Q^* || N_i)
        computed_Pi1 = h(N_s + self.current_K + Q_star + self.current_nonce)
        
        print("\nDevice-side Π1 verification:")
        print(f"  Calculated value: {computed_Pi1.hex()}")
        print(f"  Received value: {Pi1.hex()}")

        if computed_Pi1 != Pi1:
            raise AuthenticationFailed("Π1 verification failed")
        
        return N_s

    def finalize_authentication(self, N_s):
        """Complete certification (MSC₃ = {Δ, Π2})"""
        # Reconfiguration in the scheme
        self.module.reconfigure()
        self.module.evaluate()
        
        # Next session parameters
        Q_next = self.module.Q
        K_next = self.module.K
        
        # Δ = Enc_{K_i}(Q_{i+1} || K_{i+1}) in the scheme
        data = pad(Q_next + K_next, AES.block_size)
        cipher = AES.new(self.current_K, AES.MODE_ECB)
        delta = cipher.encrypt(data)
        
        # Π2 = h(Δ || K_i || Q* || N_s) - Use received Q*
        Pi2 = h(delta + self.current_K + self.current_Q_star + N_s)
        
        # RID Update in scheme
        self.RID = h(self.RID + Q_next)
        
        # Update current credentials
        self.current_Q = Q_next
        self.current_K = K_next
        
        print("\nDevice-side calculation of Π2:")
        print(f"  Δ: {delta.hex()}")
        print(f"  K_i: {self.current_K.hex()}")
        print(f"  Q*: {self.current_Q_star.hex()}")
        print(f"  N_s: {N_s.hex()}")
        print(f"  Π2: {Pi2.hex()}")

        return delta, Pi2

class Server:
    """Server-side implementation"""
    def __init__(self, initial_Q, initial_K, initial_RID):
        # Server storage in the scheme
        self.stored_Q = initial_Q
        self.stored_K = initial_K
        self.stored_RID = initial_RID
        self.session_data = {}

    def respond_to_challenge(self, device_nonce):
        """Responding to challenge (MSC₂ = {N_s^*, Q^*, Π1})"""
        # N_s (Random Numbers) in the scheme
        N_s = generate_nonce(16)
        
        # N_s^* = K_i ⊕ N_s in the scheme
        N_s_star = xor_bytes(N_s, self.stored_K)
        
        # Q^* = Q_i ⊕ K_i in the scheme
        Q_star = xor_bytes(self.stored_Q, self.stored_K)
        
        # Π1 = h(N_s || K_i || Q^* || N_i) in the scheme
        Pi1 = h(N_s + self.stored_K + Q_star + device_nonce)
        
        # Storing session data
        self.session_data[device_nonce] = {
            'N_s': N_s,
            'Q_star': Q_star  # Save Q* for subsequent verification
        }
        
        print("\nServer-side generation Π1:")
        print(f"  N_s: {N_s.hex()}")
        print(f"  K_i: {self.stored_K.hex()}")
        print(f"  Q_star: {Q_star.hex()}")
        print(f"  Nonce: {device_nonce.hex()}")
        print(f"  Π1: {Pi1.hex()}")
        
        return (N_s_star, Q_star, Pi1)

    def verify_device_response(self, device_msg, device_nonce):
        """Verify device response (MSC₃ = {Δ, Π2})"""
        delta, Pi2 = device_msg
        
        if device_nonce not in self.session_data:
            raise AuthenticationFailed("Invalid Session")
        
        session_data = self.session_data[device_nonce]
        N_s_bytes = session_data['N_s']
        Q_star_bytes = session_data['Q_star']  # Get the saved Q*

        # Π2 = h(Δ || K_i || Q* || N_s) - Using the same Q*
        computed_Pi2 = h(delta + self.stored_K + Q_star_bytes + N_s_bytes)
        
        print("\nServer-side Authentication Π2:")
        print(f"  Δ: {delta.hex()}")
        print(f"  K_i: {self.stored_K.hex()}")
        print(f"  Q*: {Q_star_bytes.hex()}")
        print(f"  N_s: {N_s_bytes.hex()}")
        print(f"  calculate Π2: {computed_Pi2.hex()}")
        print(f"  receive Π2: {Pi2.hex()}")

        if computed_Pi2 != Pi2:
            raise AuthenticationFailed("Π2 verification failed")
        
        # Decryption Δ in the scheme
        cipher = AES.new(self.stored_K, AES.MODE_ECB)
        decrypted = unpad(cipher.decrypt(delta), AES.block_size)
        Q_next = decrypted[:32]
        K_next = decrypted[32:48]
        
        # RID Update in scheme
        new_RID = h(self.stored_RID + Q_next)
        
        # Update server status
        self.stored_Q = Q_next
        self.stored_K = K_next
        self.stored_RID = new_RID
        
        return new_RID

# === Test Scripts ===
if __name__ == "__main__":
    print("=== Simulation of LR-OPUF reconfigurable authentication scheme ===")

    
    # initialization
    S0 = generate_nonce(16)
    C0 = generate_nonce(16)
    device = Device(S0, C0)

    print(f"Device initial Q: {device.current_Q.hex()}")
    print(f"Device initial K: {device.current_K.hex()}")

    server = Server(device.current_Q, device.current_K, device.RID)
    
    try:
        # Step 1: Device sends N_i（MSC₁）
        print("\n--- Step 1: Device sends challenge ---")
        N_i = device.initiate_authentication()
        print(f"device Nonce (N_i): {N_i.hex()}")
        
        # Step 2: Server Response
        print("\n--- Step 2: Server Response ---")
        server_response = server.respond_to_challenge(N_i)
        N_s_star, Q_star, Pi1 = server_response
        print(f"server send N_s*: {N_s_star.hex()}")
        print(f"server send Q*: {Q_star.hex()}")
        
        # Step 3: Device processes the response
        print("\n--- Step 3: Device processes the response ---")
        N_s = device.process_server_response(server_response)
        print(f"Device decryption N_s: {N_s.hex()}")
        
        # Step 4: Device certification completed
        print("\n--- Step 4: Device certification completed ---")
        device_response = device.finalize_authentication(N_s)
        delta, Pi2 = device_response
        print(f"device send Δ: {delta.hex()}")
        
        # Step 5: Server Verification
        print("\n--- Step 5: Server Verification ---")
        new_RID = server.verify_device_response(device_response, N_i)
        device.RID = new_RID
        
        print("\n=== Authentication successful ===")
        print(f"new RID: {new_RID.hex()}")
        print(f"new Q: {server.stored_Q.hex()}")
        print(f"new K: {server.stored_K.hex()}")
    
    except AuthenticationFailed as e:
        print(f"\n!!! Authentication failed: {str(e)} !!!")
    except Exception as e:
        print(f"\n!!! An error occurred: {str(e)} !!!")
        import traceback
        traceback.print_exc()