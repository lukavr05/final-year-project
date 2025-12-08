from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import train_test_split
import numpy as np
import warnings


warnings.filterwarnings("ignore", category=UserWarning)

data = np.genfromtxt("binary-features.txt", delimiter=",", skip_header=1)

X = data[:, :-1]
y = data[:, -1].astype(int)

unique, counts = np.unique(y, return_counts=True)
print("Number of classes:", len(unique))
print("Average samples per class:", np.mean(counts))

X_train, X_test, y_train, y_test = train_test_split(X, y, random_state=2408)

knn = KNeighborsClassifier(n_neighbors=5)
knn.fit(X_train, y_train)

print(knn.score(X_test, y_test))