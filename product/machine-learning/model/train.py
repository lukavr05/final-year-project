import time

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GridSearchCV, train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC

NUM_FEATURES = 16

print("Loading dataset...")
X = np.genfromtxt(
    "binary-features.txt",
    delimiter=",",
    usecols=list(range(NUM_FEATURES)),
    skip_header=1,
)
y = np.genfromtxt(
    "binary-features.txt", delimiter=",", usecols=[NUM_FEATURES], skip_header=1
)

print(f"Dataset shape: X={X.shape}, y={y.shape}")

X_train, X_test, y_train, y_test = train_test_split(X, y, random_state=2408, stratify=y)
X_train_pr, X_valid, y_train_pr, y_valid = train_test_split(
    X_train, y_train, test_size=0.2, random_state=42
)

pipelines_and_grids = {
    "KNN": (
        Pipeline([("scaler", StandardScaler()), ("clf", KNeighborsClassifier())]),
        {
            "clf__n_neighbors": [3, 5, 7, 9, 11],
            "clf__weights": ["uniform", "distance"],
            "clf__p": [1, 2],
        },
    ),
    "SVC": (
        Pipeline([("scaler", StandardScaler()), ("clf", SVC())]),
        {
            "clf__C": [0.01, 0.1, 1, 10, 100],
            "clf__gamma": ["scale", "auto", 0.01, 0.1, 1],
            "clf__kernel": ["rbf"],
        },
    ),
    "LogisticRegression": (
        Pipeline(
            [("scaler", StandardScaler()), ("clf", LogisticRegression(max_iter=2000))]
        ),
        {
            "clf__C": [0.01, 0.1, 1, 10, 100],
            "clf__penalty": ["l2"],
            "clf__solver": ["lbfgs"],
        },
    ),
    "RandomForest": (
        RandomForestClassifier(class_weight="balanced"),
        {
            "n_estimators": [200, 500],
            "max_depth": [4, 6, 8, None],
            "max_features": ["sqrt", "log2"],
            "criterion": ["gini", "entropy"],
        },
    ),
}

results = {}

for name, (model, grid) in pipelines_and_grids.items():
    print(f"\nTuning {name}...")

    grid_search = GridSearchCV(model, grid, cv=5, n_jobs=-1, verbose=1)

    start = time.time()
    grid_search.fit(X_train_pr, y_train_pr)
    elapsed = time.time() - start

    best_model = grid_search.best_estimator_
    accuracy = best_model.score(X_valid, y_valid)

    print(f"Best Params: {grid_search.best_params_}")
    print(f"Best CV Score: {grid_search.best_score_:.4f}")
    print(f"Validation Accuracy: {accuracy:.4f}")
    print(f"Time: {elapsed:.2f}s")

    results[name] = {
        "best_model": best_model,
        "best_params": grid_search.best_params_,
        "cv_score": grid_search.best_score_,
        "val_accuracy": accuracy,
        "training_time": elapsed,
    }

best_model_name = max(results, key=lambda x: results[x]["val_accuracy"])
best_accuracy = results[best_model_name]["val_accuracy"]

print(f"\n{'=' * 50}")
print(f"BEST MODEL: {best_model_name}")
print(f"BEST VALIDATION ACCURACY: {best_accuracy:.4f}")
print(f"{'=' * 50}")
