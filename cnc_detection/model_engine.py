import torch
import torch.nn as nn
import numpy as np
import os
import matplotlib.pyplot as plt
from sklearn.metrics import classification_report, confusion_matrix

# Thiet lap hat giong ngau nhien
torch.manual_seed(42)

class FocalLoss(nn.Module):
    """Focal Loss de xu ly du lieu mat can bang (C&C traffic rat hiem)."""
    def __init__(self, alpha=1, gamma=2):
        super(FocalLoss, self).__init__()
        self.alpha = alpha
        self.gamma = gamma

    def forward(self, inputs, targets):
        BCE_loss = nn.functional.binary_cross_entropy(inputs, targets, reduction='none')
        pt = torch.exp(-BCE_loss)
        F_loss = self.alpha * (1-pt)**self.gamma * BCE_loss
        return torch.mean(F_loss)

class CNCLSTMModel(nn.Module):
    """Kien truc LSTM 2 lop cho phan tich luu luong mang."""
    def __init__(self, input_dim, hidden_dim=64):
        super(CNCLSTMModel, self).__init__()
        self.lstm = nn.LSTM(input_dim, hidden_dim, num_layers=2, batch_first=True, dropout=0.3)
        self.fc = nn.Linear(hidden_dim, 1)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        # out: (batch, seq, hidden)
        out, _ = self.lstm(x)
        # Lay trang thai cuoi cung cua chuoi
        out = self.fc(out[:, -1, :])
        return self.sigmoid(out)

def train_engine():
    # Kiem tra ma tran dau vao
    if not os.path.exists('./matrix/X_train.npy'):
        print("[!] Khong tim thay ma tran huan luyen. Vui long chay feature_engineering.py")
        return

    # Load du lieu
    X_train = torch.from_numpy(np.load('./matrix/X_train.npy'))
    y_train = torch.from_numpy(np.load('./matrix/y_train.npy')).view(-1, 1)
    X_val = torch.from_numpy(np.load('./matrix/X_val.npy'))
    y_val = torch.from_numpy(np.load('./matrix/y_val.npy')).view(-1, 1)

    # Khoi tao model
    input_dim = X_train.shape[2]
    model = CNCLSTMModel(input_dim=input_dim)
    criterion = FocalLoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001)

    epochs = 30
    batch_size = 64
    history = {'train_loss': [], 'val_loss': []}

    print(f"[*] Bat dau huan luyen LSTM (Input dim: {input_dim})...")
    
    for epoch in range(epochs):
        model.train()
        # Shuffle batching don gian
        permutation = torch.randperm(X_train.size(0))
        epoch_loss = 0
        
        for i in range(0, X_train.size(0), batch_size):
            optimizer.zero_grad()
            indices = permutation[i:i+batch_size]
            batch_x, batch_y = X_train[indices], y_train[indices]
            
            outputs = model(batch_x)
            loss = criterion(outputs, batch_y)
            loss.backward()
            optimizer.step()
            epoch_loss += loss.item()
            
        # Validation
        model.eval()
        with torch.no_grad():
            val_outputs = model(X_val)
            v_loss = criterion(val_outputs, y_val)
            
        history['train_loss'].append(epoch_loss / (X_train.size(0)/batch_size))
        history['val_loss'].append(v_loss.item())
        
        if (epoch + 1) % 5 == 0:
            print(f"Epoch [{epoch+1}/{epochs}] | Loss: {loss.item():.4f} | Val Loss: {v_loss.item():.4f}")

    # Luu ket qua danh gia
    print("[*] Dang tao bao cao danh gia...")
    model.eval()
    with torch.no_grad():
        preds = (model(X_val) > 0.5).float().numpy()
        report = classification_report(y_val.numpy(), preds)
        with open("report.txt", "w") as f:
            f.write(report)

    # Ve bieu do Loss
    plt.figure(figsize=(10, 5))
    plt.plot(history['train_loss'], label='Train Loss')
    plt.plot(history['val_loss'], label='Val Loss')
    plt.title('Model Convergence (Focal Loss)')
    plt.legend()
    plt.savefig('training_metrics.png')
    
    # Luu model
    torch.save(model.state_dict(), 'cnc_detector_model.pth')
    print("[SUCCESS] Mo hinh da duoc luu tai: cnc_detector_model.pth")

if __name__ == "__main__":
    train_engine()
