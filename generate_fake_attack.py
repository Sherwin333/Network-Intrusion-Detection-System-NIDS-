import pandas as pd
import random

def generate_fake_attack(file_path, num_samples=500):
    attack_data = []

    for _ in range(num_samples):
        src_ip = ".".join([str(random.randint(1, 255)) for _ in range(4)])
        dst_ip = ".".join([str(random.randint(1, 255)) for _ in range(4)])
        frame_len = random.randint(40, 1500)  # random packet size
        count = random.randint(50, 500)       # abnormal high count
        dst_bytes = random.randint(0, 10)      # very low bytes sent
        src_bytes = random.randint(10000, 50000)  # very large bytes sent
        
        attack_data.append([src_ip, dst_ip, frame_len, count, dst_bytes, src_bytes, "attack"])

    attack_df = pd.DataFrame(attack_data, columns=['ip.src', 'ip.dst', 'frame.len', 'count', 'dst_bytes', 'src_bytes', 'labels'])
    attack_df.to_csv(file_path, index=False)
    print(f"Fake attack data generated and saved to {file_path}")

if __name__ == "__main__":
    generate_fake_attack("data/fake_attack.csv", num_samples=500)
